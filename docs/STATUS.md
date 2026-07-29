# KARST — implementation status

> **REFERENCE, NOT FOR PRODUCTION.** This is an executable check of the
> specification (`../KARST_SPEC.md`), not deployment-ready code. Below is an
> honest map: what works for real, what is stubbed, what is blocked on an external
> dependency. **The code is the source of truth**; on any discrepancy, fix this
> file, not the other way around.

Last reconciled: `impl/admission` (§7) + `impl/node` (message-path skeleton +
socket transport + epoch wiring + durable/out-of-order blob store) + `impl/client`
(client core, CLI `karst`, multi-homing) + `impl/desktop` (the Tauri desktop) +
Clippy clean. See **"What landed since the last reconcile
(2026-07-20 → 2026-07-24)"** immediately below for the current delta (proxy identity, the feed +
publications/stories, the session simultaneous-first-contact fix, duress Tier 1, the PoW door).

## What landed since the last reconcile (2026-07-24 → 2026-07-25)

Newest batch first (all in `impl/client` + `impl/node` + `impl/desktop`, tests green):

- **Session — simultaneous first contact fixed.** Two peers who each PQXDH-initiated before either
  received used to split (invisible messages, orphaned image chunks, OOM). Now both halves are held
  per peer (outbound in `sessions`, the peer's responder in `inbound_sessions`), re-delivered openers
  dedup by `drop_seed`. A **Reconnect** button (`forget_peer`) recovers a pair already split on an
  older build.
- **UI responsiveness + anti-fingerprint + scale.** The `poll` command is now `async` (Tauri v2 runs
  sync commands on the main thread — it froze the UI every 4 s). The poll cadence is **jittered**
  (~2.5–6.5 s, no fixed period — a constant 4 s was a timing fingerprint). The chat is **windowed**
  (last N + "Show earlier"), so a 10k-message history no longer builds at once. The poll now **drains
  the mailbox** (up to MAX_DRAIN_PAGES) instead of one fetch page, so a multi-image post lands in a
  couple of cycles instead of minutes. And the feed's read commands (`feed`, `post_images`,
  `post_attachments`, `peer_avatar`, `contacts`, `history`, …) are now **async** too (they were
  blocking the main thread), with the feed's media fetches fired in **parallel** — the feed loads
  responsively instead of one blocking round-trip at a time.
- **Multi-attachment posts.** Several photos + files per post (`PostAttachmentManifest`,
  `feed_attachments` sidecar, `send_post_attachment`), gallery + file-card render, lazy-loaded.
- **Post media rides the BLOB store now (fixes the dropped-image bug).** The inline path fanned
  ~90 session chunks PER attachment PER recipient into the recipient's mailbox; a 4-image post =
  ~360 seals into a 256-seal-capped mailbox, so the later images bounced off `MailboxFull` (the
  "one of four published, the rest didn't"). The new `PostAttachmentRef` uploads each attachment as
  a **per-recipient blob** (`send_post_attachment_blob` → `blob_upload`, a fresh random
  `blob_id`+`key` per contact so the relay never sees "one blob, whole audience" — the correlation
  the inline path was chosen to avoid) and deposits ONE tiny pointer in the mailbox. The bulk now
  lives in the blob store (its own ceiling, not the 256 cap). Receive reuses the FileRef machinery:
  `recv_session` persists the ref as a durable pending fetch (before the ack), driven by
  `drive_pending_post_attachments` into the same `feed_attachments` sidecar the UI already reads
  (zero UI change), then a coalesced feed nudge re-hydrates. **Honest costs:** N uploads of the same
  image (one blob per recipient — the price of no audience-correlation); a recipient offline past the
  7-day blob TTL misses the media (the post TEXT still shows); the per-attachment size stays capped
  at 96 KiB this slice (raising it is a deliberate follow-on, not a side effect). The desktop composer
  sends every photo as an attachment, so this IS the live path; the legacy single-image
  `send_post_image` stays inline (CLI/compat only — one image fits the mailbox). e2e-tested end to end
  over the socket with the real 4-image case (`post_attachment_blob_round_trips_into_the_feed_sidecar`).
- **Feed follow-ups + fixes.** Subscribing to a CONTACT is now instant (their `JoinRequest` is
  auto-accepted, like channel mode) — no approval dance between people who already added each other; a
  stranger to a private account still queues. The chat's right-side Posts panel gained a Subscribe
  button and now renders post PHOTOS (it was text-only — an image post showed blank there; the main
  feed always rendered them). A received file now saves via a NATIVE dialog (`save_received_file`,
  streamed) — WebKitGTK silently ignores the webview `<a download>` blob trick, which is why "can't
  save a received file" happened.
- **Send-side multi-homing (failover).** `send_session_multi` sends via the primary and, if it's down
  (message stayed queued), flushes that EXACT sealed ciphertext through a live secondary — no
  re-encrypt, no ratchet double-advance; the desktop poll retransmits across every relay. So a
  blocked primary no longer strands an ongoing conversation (first-contact-via-a-secondary is a
  documented residual). e2e-tested.
- **Admission credentials are PER RELAY (CRYPTO-24).** An account used to hold exactly one
  `capability.dat` and present it to every relay. Against dev relays that works — they all admit the
  same globally known dev capability — but in production a capability is relay-specific (a Private
  relay mints a random `capability_id + secret`; a Public relay derives a stateless secret from its
  own issuer key), so a second relay answers `UnknownCapability`/`BadMac`. The finding named send
  failover; it was **worse than filed**, because CREATING a bundle slot is metered too
  (`handle_publish`, CRYPTO-18): the account never became reachable on a backup relay at all, so
  receive-side multi-homing was broken as well, not just the failover. It also handed every relay the
  same `capability_id`, linking one account's traffic across independent operators. Now
  `capabilities.dat` is a map `relay-id → capability`; there is no way to ask for "the" capability
  without naming the relay (`Store::load_capability_for`), `karst dev-cap`/`import-cap`/`join` write
  against a named relay, and `publish_all` skips — loudly — any relay this account holds no
  credential for rather than presenting another's. Pinned by
  `multi_homing_presents_each_relay_the_credential_that_relay_issued`, which runs against two relays
  admitting DIFFERENT credentials (the dev cap deliberately not issued) and covers both halves.
  **What this does NOT do: it does not acquire credentials.** Failover works only for relays the
  account has actually joined or imported an invite for; for the rest it now fails honestly (skip +
  reason) instead of silently presenting a credential that would be rejected. The desktop therefore
  no longer seeds the forgeable DEV capability on its own: seeding it per relay would have handed a
  REAL relay (one whose `earn_capability` just failed because it is invite-only) a public-secret
  credential and made the honest skip unreachable — the `unwrap_or(dev_capability())` shape A8-11
  removed from the send path, one layer up. The client cannot tell a dev relay from a real one, so
  it does not guess: the demo states it with **`KARST_DEV_CAP=1`** (loud, per relay, never
  overwriting a real credential), the same way `KARST_INSECURE_FAST_KDF` is stated rather than
  inferred. Auto-earning a
  capability when a relay is discovered is a deliberate non-goal here — it would make discovery emit
  a PoW admission round trip on its own. The node-side half is now closed too (CRYPTO-25): a private
  relay mints ONE credential PER INVITEE (`karst-relay invite new|list|revoke`), each with its own
  `capability_id` — so the quota tracker, which meters by that id, no longer pools every invitee
  into one bucket, a single person can be revoked without touching the others (effective on the
  next request, not at the next restart), and the invite file now carries the relay-id and address
  it belongs to instead of being a bare credential the client had to be told about out of band.
  Pinned by `revoking_one_invite_leaves_every_other_invite_working`, which discriminates on the
  property that matters: after the revoke, that invite's proof is refused and every other invite
  still verifies.
- **Metadata hardening (Loopix-style) — status.** The impactful pieces are already shipped and
  verified: the relay fetch response is a FIXED 16 000-byte page whether it carries 0 or `FETCH_CAP`
  seals (§2.2 — message COUNT never leaks through response length), polling is jittered, and messages
  ride fixed session size-buckets. The final layer — Poisson cover DEPOSITS to mask the timing of a
  real send — is now shipped as an opt-in toggle (Security card): a self-addressed dummy deposited via
  the exact real send path on an exponential (mean ~45 s) schedule, so it is byte-indistinguishable
  from a real send (always-on bandwidth; effectiveness scales with adoption). e2e-tested. Deniable-
  encryption hidden volumes (multipassword Tier 2) are now shipped too — see Multipassword Tier 2.
- **Quota — operator-configurable.** The per-capability quota is now a relay policy: raised dev cap,
  a setup-wizard "Admission budget" section, `KARST_RELAY_QUOTA`, live `karst-relay quota` over the
  admin socket, and disable-able. Enforced as a CEILING per request (`Quota::clamped_by`) so a change
  bites existing caps and a forgeable dev cap can't exceed it. Now has an explicit **`bytes-only`**
  preset too (request cap = `u32::MAX`, a real byte ceiling) for operators who want to meter by
  VOLUME, not packet count — the honest name for the byte-primary posture, alongside chat-only /
  media-friendly / unlimited (wizard + `KARST_RELAY_QUOTA` + live `karst-relay quota preset`).
- **Contacts — mutual-consent requests + lifecycle.** Adding sends a `ContactRequest` with your
  profile; the recipient sees who's asking and only on **Accept** do names/bios cross (`ContactAccept`).
  Name is now OPTIONAL (resolves to the peer's self-declared name, else a short IK, always renamable);
  a per-contact **channel picker** chooses which of your channels they see. Removing a contact now
  WIPES the conversation (history+session+profile) so a re-add starts clean (fixed a resurrection
  bug), and optionally sends a `DeleteConversation` request (they choose whether to clear their copy).
  The recipient gets a one-tap **Clear conversation** (a request flashes that button when their chat
  is open) — honoring it is their choice, never a forced wipe.
- **Identity UI.** Dropped the privileged "your address (IK)" from Profile — no single identity; the
  Connection-channels card moved to second in Settings (it IS your addresses).
- **Relay auto-start survives reboot.** `install-node.sh` already installs a systemd `--user` unit
  (EnvironmentFile pins `KARST_RELAY_HOME` → the relay-id is stable across restarts, so clients
  reconnect on their own). The gap was that a `--user` service starts only at *login*: the installer
  now **offers to enable linger** (`loginctl enable-linger`), so the relay actually comes back after a
  reboot, with a graceful printed-hint fallback if sudo is declined. The unit also got `RestartSec=2`
  so a cold-boot bind race backs off instead of tripping systemd's restart-burst limit.
- **Conversation vs contact — DM anyone without "adding" them.** You can now message any IK without
  making them a contact: a chat-only peer is flagged in a new `unconfirmed.dat` sidecar (NOT a field
  on the postcard-positional `ContactRecord` — that would orphan every existing contact on disk; a
  sidecar makes migration inherently safe, guarded by a test). A conversation-only peer's
  self-declared name/bio/avatar and their posts stay HIDDEN (shown as a short IK) and YOUR profile /
  posts / avatar never fan out to them, gated by `is_confirmed_contact` on both send and receive
  (`is_feed_source` also lets a subscribed channel through). "Add to contacts" is a separate explicit
  action (the existing mutual-consent `ContactRequest`/`ContactAccept`), and an incoming request now
  surfaces ON the requester's own chat — name revealed + a "wants to add you" Accept/Decline card —
  instead of a floating panel entry the user couldn't tie to the conversation. Two identity bugs fixed
  along the way: the accept/add reply went out from the DEFAULT proxy instead of the one the request
  arrived on, so the peer filed you as a phantom SECOND contact under a different IK — now it replies
  from `proxy_for_contact` (the pinned receiving proxy, the §7.4/#92 "reply from the right proxy"
  pattern), so each person stays ONE identity (new e2e test
  `contact_accept_comes_from_the_proxy_that_received_the_request`); and the open chat now re-renders
  from the FRESH contact after add/accept so the header/badge actually update.
- **Channels card — burned vs live.** The Connection-channels (disposable proxy/IK) list keeps live
  channels up top (copy / migrate / burn) and folds burned ones into a collapsed, dimmed, "N burned"
  section (tagged, no dead actions); both lists scroll past ~230px so many channels never blow the
  card open.
- **Feed reworked into a subscribe model (posts decoupled from contacts).** The feed now shows ONLY
  accounts you SUBSCRIBED to (`is_feed_source` = subscribed channels, not contacts), and publishing
  fans out to your SUBSCRIBERS (not every contact). Per-post visibility: the audience picker lists
  your subscribers (new `subscribers` command) — default "all subscribers", narrowable to specific
  ones down to a single subscriber; a narrow post reaches only them. **Live pull** for the "visit a
  profile you don't follow and view it" case (serverless — posts live on the author's device): a new
  `PostsRequest` asks the author, who answers WHILE ONLINE with their recent PUBLIC posts only
  (`public_posts.dat` marks which own posts are public; a narrow post is never served to a puller); a
  `pulled.dat` sidecar lets the reply through the feed gate into the profile view. A Subscribe pill
  turns a one-off peek into a standing follow. The relay sees the pull request (who-views-whom) — the
  honest cost chosen over subscribe-only. Wire e2e-tested. Also: native `<select>` popups (which the
  GTK webview renders off-theme) replaced by a custom on-theme dropdown, and the feed compose bar's
  Publish button aligned to the pill row.

## What landed since the last reconcile (2026-07-20 → 2026-07-24)

The sections below this one were written earlier and remain accurate as design; this is the honest
delta of what has SHIPPED since, in the done / partial / abandoned framing. The code is still the
source of truth — where a feature is named, the crate is given. **531 tests pass in the default
build; clippy clean.**

### Done (real, tested)

- **Proxy-identity model — the root has no address (`impl/client`, `impl/desktop`).** What the
  phrase+password unlock is a seed and a local hub with NO IK and no network presence; the only
  things on the wire are disposable HD-derived **proxies** (`derive_proxy`, a frozen domain apart
  from the root `derive`). `Store::as_proxy(n)` namespaces each proxy's network state
  (sessions/opks/handles) via `net_file`, while history/feed/contacts stay on the shared root
  paths — one unified inbox. Desktop publish/poll/send iterate active proxies; the root never
  appears on a relay. Connection-channels UI (create / burn / copy a channel) and **channel
  migration** (move keepers off a burned channel, authenticated by arrival on the old session) ship.
- **Publications, stories & a feed (`impl/desktop` + `impl/client`).** A server-LESS timeline:
  posts fan out E2E to contacts ∪ subscribers, deduped by (author,id), stored in a local feed with
  a **per-author cap** (a flooding contact evicts only their own oldest) under a global cap.
  **Stories** are ephemeral posts that self-destruct 24h out (absolute `expire_at`, dropped on
  arrival if already dead). **Inline images** in posts/stories are chunked E2E slices reunited by
  post id into a sealed `feed_images.dat` sidecar (no relay blob). Retractions drop a post (and its
  image) from every feed.
- **Session delivery — simultaneous first contact (`impl/node`).** Two peers who each PQXDH-
  initiated before either received used to split (each on a session the other never learned →
  invisible messages, orphaned image chunks, an OOM). Now both halves are held per peer — the
  outbound ratchet in `sessions`, the peer's responder in `inbound_sessions` — as two one-way
  chains; re-delivered openers dedup by `drop_seed`. **Reconnect** (`forget_peer` +
  `reconnect_peer`, a button in the contact's Encryption panel) recovers a pair already split on an
  older build.
- **Multipassword / duress — Tier 1 (`impl/client`).** Decoy / wipe / dead-man keyslot foundation
  (threat model A′).
- **Multipassword Tier 2 — deniable CONTAINER with a hidden ACCOUNT (`impl/client::container` +
  `impl/desktop`, opt-in, UNDER EMBARGO — not announced).** Supersedes the earlier note-based
  `hidden.dat`. One fixed-size `container.dat` of all-random bytes, byte-indistinguishable from noise
  without a password; holds a whole serialized account per compartment (format-(b) blob + append-only
  history log, in-place region writes so a save never rewrites the whole file), with an in-container
  8-slot keyslot table so the number of passwords never leaks. **Three passwords:** P1 (main, protect),
  P2 (a full HIDDEN account — not a note), P3 (main, blind-cover), plus Wipe (whole-container erase). The
  management slot-directory is sealed under the P1 key, so revealing P3 under duress cannot enumerate
  P1/P2 (test-pinned). Hidden account materializes into a **VERIFIED** RAM/tmpfs work dir (deleted on
  lock) — the mount TYPE is checked against `/proc/mounts`, and if no RAM-backed store can be proven the
  hidden account **refuses to open** rather than falling back to disk (it used to fall back silently to a
  predictable `base/.hidden-work`, which voided this claim on macOS/Windows/minimal containers; a main
  account is unaffected). It also refuses
  disk-export + bulk media (zero external artifacts), and defaults to OFFLINE (emits no network traffic
  until a deliberate sync). GUI-verified end-to-end: create a 64 MB container account, add a hidden
  account, both open with their own password, container size unchanged. **Honest ceiling (say it):
  deniable at rest on disk + while offline; NOT deniable against an adversary with relay/network logs
  once the hidden account goes online** (circuit isolation + timing settings deferred — see #123).
  32 container tests. Desktop: `container_create/unlock/flush/active/hidden/add_hidden`,
  `net_offline/set_net_offline`, `Vault::adopt`.
  **Container is the authority for the work dir (A3-3, fixed).** Opening a compartment now makes the
  work dir EQUAL its snapshot — `restore_dir` clears the directory first instead of overlaying the
  snapshot onto whatever was left there. A visible account's work dir (`<vault>/work`) survives
  between sessions, so the overlay let deleted contacts/settings/sidecars come back and be
  re-snapshotted (permanent resurrection), and could mix two generations of state file-by-file with
  nothing reporting it. A blob that fails to decode is refused *before* anything is removed. **Named
  cost:** work that never reached a `save()` is discarded cleanly at the next open rather than left
  behind torn — safe for received mail (ACKs are deferred behind the commit, so it redelivers), a real
  loss for a queued `flush_outbox` send or an in-progress download, which have no relay copy. Test:
  `reopening_a_compartment_replaces_the_work_dir_instead_of_merging_into_it`.
  **One writer per container (A3-8, fixed — UNIX only).** `Container` holds an exclusive `flock` on
  `container.dat` for its lifetime, so a second window (or a second instance in one process) is
  refused rather than racing. Two writers previously shared one `<container>.tmp` and could rename an
  interleaved mixture over the file — losing EVERY compartment, not just the loser's changes — while
  `load` could unlink another process's in-flight save. **No equivalent on non-UNIX platforms**: a
  lock *file* is not available to us, because a hidden account's directory must hold `container.dat`
  and nothing else. A lock conflict (and an over-ceiling container) is reported with a distinct
  `io::ErrorKind` so `container_unlock` does not fold it into the opaque "wrong password" it must
  return for a genuine open failure — a user with a correct password should never be told otherwise.
  `wipe` deliberately does NOT re-take the lock: a wipe that lost the relock race would report
  failure for a container it had just erased. Test:
  `a_second_live_container_over_one_file_is_refused_until_the_first_is_dropped`.
  **Container size is a RAM budget, capped at 1 GiB (A3-9, fixed).** The whole file lives in a
  `Vec<u8>`, and the desktop passed `size_mb` from the frontend through unchecked;
  `client::container::MAX_CONTAINER_BYTES` now refuses an oversized container at `create` (before the
  allocation) and at `load` (by `stat`, before the read). Memory-mapping would not lift this: format
  (b) stores one sealed blob per compartment, so a save buffers the whole snapshot and its whole
  ciphertext regardless — peak ≈ 2× the container size, of which only the file term is mmap-able.
  1 GiB ⇒ ~384 MiB of usable account. Test:
  `a_container_over_the_ram_ceiling_is_refused_at_both_create_and_load`.
  **Receive durability (SEC-34, fixed).** A container-backed session's `Store` is a materialized
  working copy; the authority is the container, written by a separate later `save()`. Receiving used
  to ack the relay — telling it to delete its only copy — as soon as that working copy was written,
  and the container save came later, was skipped entirely when a poll produced no UI events, and only
  warned when it failed. Now `client::recv_session_multi` **does not ack**: it returns
  `DeferredAcks`, whose only sender (`commit_then_send`) runs the caller's commit first and sends
  nothing if it fails, and the desktop poll keys that commit off **leases taken**, not off UI output.
  A failed commit therefore leaves the batch leased on the relay, to redeliver. Test:
  `a_failed_container_commit_leaves_the_batch_redeliverable` (real capacity failure, reopened
  container, relay-clock lease expiry), plus `a_control_only_batch_still_carries_a_commit_barrier`.
  **Named limits.** (a) "Redeliverable" means *after a relock/restart*: within the same session the
  work dir still holds the advanced ratchet, so a redelivery fails closed and shows as nothing — no
  loss, but no in-session recovery either. (Since A3-3 the relock/restart half is cleaner than it
  was: the reopen resets the work dir to the container's snapshot outright, so the ratchet really
  does return to the last committed state instead of being partly overlaid by leftovers.) A failed
  commit DROPS its receipts rather than deferring them to the next successful save, so those messages
  occupy relay mailbox slots until the deposit TTL sweeps them (bounded, never lossy — the copy that
  matters is the container's). (b) The **ratchet rollback itself is not fixed**: reopening a
  compartment restores the container's snapshot over the work dir — now a full replace rather than a
  merge, so a stale snapshot rolls the account back wholesale — and a rollback deeper than `MAX_SKIP`
  can still wedge a conversation. Deferring the ack removes the message LOSS, not the rollback.
  (c) Only the receive path is gated. Other writers of a container-backed work dir — `flush_outbox`,
  the spawned download/attachment threads — are still durable only at the next container save, and
  since A3-3 their un-saved work is *discarded* at the next open rather than surviving in the
  directory. Nothing is deleted from a relay on their behalf, so a rollback costs a redundant resend
  or re-download, not mail — but the queued item itself does not survive the reopen. (d) The
  quarantine/replay log is **not** a mitigation here: it lives in the work dir, so it rolls back with
  everything else.
- **Public-node admission door (`impl/admission`, `impl/node`).** A stateless proof-of-work → a
  short-lived capability, so a public relay admits strangers without an invite and without keeping
  per-client state at the door.
- **Interactive relay setup + graceful stop (`impl/node` `karst-relay`).** A sectioned setup
  wizard covers the whole config surface (admission / network / identity / transport incl. wss+TLS /
  federation / storage), plain-English prompts and errors, and a `stop` admin verb (no kill).
- **Full-UI i18n (`impl/desktop`).** Nine-language localization of the desktop UI + status keys.

### Partial / known gaps (works, but with a stated limit)

- **Multi-homing — both sides now.** Receive polls the WHOLE relay set (a dead relay no longer costs
  the healthy ones their mail) and the SEND side fails over across relays (`send_session_multi`), so a
  down primary no longer strands a deposit. e2e-tested. Erasure-coded multi-relay deposit (one message
  split across several relays at once) is the remaining, larger slice.
- **Feed image render cost.** `feed_to_posts` re-base64-encodes every feed image on every `feed`
  call, and the UI reloads the feed on each post event — noticeable jank with several large images.
  A cache / lazy-load is the fix; correctness is unaffected.
- **Public tier, next up:** blinded directory + node-list gossip (4c) — designed, not built.

### Abandoned / won't do

- **In-repo transport obfuscation.** The SOCKS5 pluggable-transport SEAM stays; KARST will not ship its own
  obfs/uTLS/ECH implementation (the spec calls this "an interface, not an implementation of
  its own"). Front the relay with your own onion/i2p/PT and hand out that address.

## Live end-to-end verification (2026-07-19)

Not just component tests — the assembled system was run for real. A `dev`-mode relay + two
`karst` CLI clients on it: both create accounts, publish §2.1 bundles, and exchange text **both
directions** (delivered, decrypted, attributed to the sender's IK); a file sends and arrives
**byte-identical**. The Tauri desktop (`karst-desktop`, brand cyan) LAUNCHES and renders its
welcome screen. So relay + client + UI work together, not only in isolation.

**At-rest sealing of received files, stated precisely:** the **large-file blob path seals
received files at rest on every client** (`SealedFileWriter`, `files/<id>.dat`) — including the
CLI, which now unseals them on demand with `karst export-file` (and lists them with `karst
files`). Only a **small INLINE file received on the CLI** still lands in `received/` in the clear
(a dev convenience). Vault secrets (seed, history, sessions, capability) are sealed on both. So a
blob-path file is encrypted at rest everywhere; the remaining gap is inline files on the CLI.

## Scope

- The `impl/admission` crate — the **admission path §7**: how a node decides
  whether to admit an incoming request without spending more resources on
  unauthorized traffic than the sender spent.
- The `impl/node` crate — a **working skeleton**: the MESSAGE path (Alice → relay
  → Bob) with a real admission handshake and an E2E envelope (classical-only, see
  below), over a real TCP socket **inside a Noise session (§15)** — the traffic is
  encrypted and the relay is authenticated to the client.
- The `impl/client` crate — the **Linux desktop client** (CLI `karst`): stores
  the identity + capability on disk (0600), sends/receives via `SocketTransport`.
  The first thing usable by hand between two processes/machines.

**Not yet implemented** (present in `KARST_SPEC.md`): **in-repo transport obfuscation** — the SEAM
exists (a SOCKS5 adapter routes through an external PT), but there is no in-repo
obfuscated transport and there won't be (the spec: "an interface, not an implementation of
its own"); ECH/domain-fronting, uTLS fingerprint, the full Path Manager + rich
`Capabilities`/`probe`/`migrate`, profiles (Normal/Private/Anonymous) — though
**connect-level path failover AND client multi-homing across several relays (§15) ARE
implemented** (a request tries a path list; receive polls the whole relay set, and a dead relay
no longer costs the healthy ones their mail); rendezvous discovery without a global list (§12;
publish/fetch bundle already exists),
mix/mailbox routing (§10), erasure coding (§13), calls (§21), the economic layer
(§19), duress/panic (§20), the **Android client** (the `client` core is ready to
be reused via JNI, the JNI itself is a separate slice). The **shipping desktop GUI is now the Tauri
client** (`impl/desktop`, web frontend on the brand design): messaging, on-disk history, the
safety number (OOB verification of the IK), profiles, large-file transfer with a progress bar,
route offers, and **multi-homing** (configure backup relays, live per-relay reachability). The
older egui client has been REMOVED (2026-07-27) — the Tauri desktop is the only GUI.

**File transfer — the inline path's boundary (named):** ≤48 KiB (≤48 chunks + a
manifest). The binding limit is **not** the mailbox (`MAX_FETCH_SEALS=256`) but
the **capability quota** on the admission path: each chunk is one relay request
and the dev-cap allows `max_requests=100` per 600 s window, so a file past
~100 chunks silently hit `CapabilityQuota` mid-send. 48 chunks + manifest = 49
requests leaves ~50 for concurrent text in the same window; anything larger goes
the blob path below (a discriminating ~150 KiB worker test guards the old dead
zone — revert `MAX_FILE_CHUNKS` to 240 and it goes red). Reassembly lives in the
memory of a live process (the worker keeps a
`Reassembler` between polls; a one-shot CLI `recv` — a file into a single
mailbox). **Stale unfinished transfers are now EVICTED** (`Reassembler` cleaned up
completed and corrupted ones; a half-assembled file — a failed `send_file` — used to
linger until restart, so ≥8 from one peer exhausted `MAX_CONCURRENT_TRANSFERS`). Each
`Partial` now carries a `last_seen` (refreshed on every chunk, so an actively-arriving
transfer is never touched), and `reap_stale` drops any idle longer than
`STALE_PARTIAL_SECS` (5 min) — run on each new manifest, so a dead transfer never pins a
slot. The crypto is the same (a file = ordinary plaintext in an envelope, zero new crypto
below the client).

**Large files — the §15 blob path (dual-path; small files still use the inline path
above).** Files over the inline 48 KiB limit ride an **E2E-encrypted blob** parked
on the relay, so they can be delivered offline and are effectively unbounded (capped,
not 240 KiB). Per file: a fresh random key `K` and a random `blob_id`; the file is
sealed in 60 KiB chunks with `ChaCha20-Poly1305`, each chunk's position
(`blob_id ‖ index ‖ count ‖ is_last`) bound in the AAD (+ index in the nonce), so the
relay — which only ever holds ciphertext — cannot reorder/truncate/splice/relabel
undetected; a plaintext SHA-256 is the end-to-end backstop, verified incrementally.
Both directions **stream to/from disk** (peak RAM O(chunk), not O(file)). A small
`FileRef {blob_id, K, hash, name, size, count}` travels inline over the session; the
recipient downloads + decrypts + verifies. `BlobStore` is disk-backed, per-blob /
per-sender / global byte-capped, and TTL-swept (7 days) like the mailbox; downloads are
cookie-gated, uploads are cookie- **and capability-gated** + metered (see the DoS-attribution
bullet below). The **index is DURABLE and chunks may arrive
OUT OF ORDER** — each chunk is its own file (`<id>.c<index>`) written atomically (temp + fsync +
rename, so a chunk file is whole or absent, never torn), plus a small `<id>.meta` header sidecar;
`BlobStore::open` rebuilds the index by scanning which chunk files survived (across gaps), drops
junk + `.tmp` leftovers, and TTL-sweeps. So a parked multi-GB upload SURVIVES a relay restart,
and the client can **pipeline** several chunks in flight at once. The **upload is resumable** (it
continues from the relay's watermark after a crash) and rides **one Noise session per file**
(reused, hard-bounded connection) instead of a fresh handshake per chunk. Recovery is client-crash- AND
relay-restart-safe; a relay that wipes its disk still loses the blob (no recovery
possible).

**Resume across a CLIENT restart (A4-1, fixed).** The relay owns a blob by the `client_addr` on
its FIRST chunk, and that address used to be the client's *session pseudonym* — fresh random bytes
per `Relay`, i.e. per process, deliberately never persisted. So a restarted client came back as a
stranger and was rejected ("blob owned by another sender") on every retry until the 7-day TTL swept
the partial: the resume record survived, the identity that owned the bytes did not. The put path
now sends `blob::owner_token(K, blob_id)` instead — derived from the per-file key the resume record
*already* persists, so ownership is durable exactly when resumability is, and is per-blob where the
pseudonym was per-process (the post-upload `verify_durability` spot check uses the same handle, since
leaving the pseudonym on that GET would have re-linked the very blobs the handle separates). That is
**not** anonymity: one connection uploading blob after blob still correlates by IP and timing; what
it removes is a stable identifier the client was handing over for free. Ordinary downloads — the
recipient's side — still carry a session pseudonym. The desktop upload path was worse than that: it called the non-resumable entry with a
fresh random `blob_id`+`key` every time and wrote no record, so the GUI had no resume at all; it now
keys the same persisted record the CLI does. **Honest limits:** the GUI receives file bytes from the
webview, not a path, so it cannot resume unattended on restart — the user re-picks the same file and
the record (keyed by content hash) continues from the watermark. And the relay's per-sender caps
(`MAX_SENDER_BYTES`, `MAX_BLOBS_PER_SENDER`) stop binding honest clients, since each blob is now its
own "sender"; what still bounds a relay is the per-blob cap, the global store cap, and the
per-capability blob quota (a RATE, not a residency bound). A hostile client always minted a fresh
`client_addr` per blob at zero cost, so nothing that was actually holding is lost — but keeping
per-client aggregation *and* durable ownership *and* cross-blob unlinkability needs the relay to
treat ownership as a proof and meter by `capability_id`, which is a relay-side change.

Tests: crypto tamper cases (byte-flip / wrong key / swap / truncate /
forged-count all detected), an end-to-end blob round-trip through the real relay
socket, **a parked blob recovered + downloaded byte-identical through a restarted
relay**, **an upload resumed after the CLIENT restarted** (all in-memory state dropped, rebuilt
from disk — RED before the fix with "blob owned by another sender"),
store-level recovery/torn-tail/TTL-on-recovery/junk cases, a ~745 KiB file
through the full GUI worker path (`Cmd::SendFile` → blob → `FileRef` → download)
byte-identical, and a ~150 KiB file that guards the old inline/blob dead zone.

**Named tradeoffs of the blob path (the deliberate fat-relay side):**
- **The relay now holds bulk data** — a fatter relay than the minimal mailbox
  (more to store), chosen explicitly for offline large-file delivery. Mitigated: it
  is E2E ciphertext (a lost or stolen disk yields nothing without `K`, which is only in the
  recipient's E2E `FileRef`), capped, and TTL-swept.
- **Large-file transfer leaks size + timing** to the relay and on-path observers (a
  blob is a distinct wire size class; "X uploaded ~N MB, Y downloaded it") in a way
  the padded small-message path does not. Inherent to bulk transfer; named, not hidden.
  Lowering the inline threshold from 240 KiB to 48 KiB (the quota fix above) widens
  this slightly: a 48–240 KiB file that used to hide as padded mailbox seals now rides
  the blob wire class and leaks its "file-ness". Strictly better than the prior state,
  where those files silently failed rather than transferring at all.
- **Blob-store DoS attribution, stated as it now is (CRYPTO-15 / A5-1 — closed).** The upload
  path is no longer cookie-only: `admit_blob_put` verifies a **capability proof** and meters the
  chunk's bytes against a **separate per-`capability_id` blob quota** before any file I/O. It does
  this without the `Scope::BlobUpload` the audit asked for — the proof is verified under
  `Scope::MessageDelivery` and the classes are kept apart by the required `blob_put_nonce` SHAPE,
  checked *before* the HMAC, so a proof minted for the message path cannot be replayed here and
  vice versa. Deliberate residuals: (a) the quota is a rate over a tumbling window, so it bounds how
  fast one credential pushes bytes, not how much it keeps parked for the 7-day TTL; (b) `client_addr`
  is still self-declared and now per-blob, so the per-sender caps bound nothing an attacker cares
  about — the per-blob cap, the global cap and the TTL do; (c) blob **downloads** stay cookie-only
  by design (egress bandwidth is a different resource with its own attribution question, named in
  `handle_blob_get` rather than folded in). With the public dev-cap anyone can still authenticate,
  so on a dev relay this meters rather than gates.
- **Transfer no longer blocks the worker thread (DONE).** The long, ratchet-free blob
  work (`blob_upload`/`blob_download`) runs on a spawned thread; the worker keeps
  polling/sending, and only the tiny final `FileRef` uses the ratchet (still on the
  worker thread — single-threaded, no mutex). A progress bar + ✕ cancel render in the
  message bubble (both directions), throttled at 512 KiB. **Test-verified:** the
  **send** side has three discriminating tests (intermediate progress streams; a quick
  text overtakes an in-flight upload → off-loop proven; cancel aborts + worker stays
  responsive); the **receive** lifecycle (`FileIncoming`→`FileProgress`→finalize-by-id)
  was covered by a worker e2e test + a controller unit test. **Screenshot-verified**
  at the time (a live progress bar advancing 1%→4%→29%→50%→80% during a real 120 MB
  upload, with the ✕ cancel button and an interactive composer) — on the legacy egui
  client, which has since been removed; the Tauri desktop carries this feature now.
- **Latent, named (not fixed):** (a) the worker no longer self-terminates on UI close —
  `run` holds its own `cmd_tx` clone so `cmd_rx` never sees `Disconnected` (that arm is
  now dead; masked by process exit). (b) A failed/cancelled *receive* drops its bar but
  shows no failure cue — the bubble footer renders delivery status only for `from_me`
  messages, so a received file that fails/cancels reads as a plain "📎 name". Cosmetic.

## Relay policy & verifiable trust (2026-07-20)

The blob store's restart behaviour is the operator's choice, a relay advertises what it does, a
client can prefer relays that match, and — for the one claim that admits it — a client can PROVE
the relay is telling the truth. Four slices, deliberately honest about what is and isn't checkable.

- **Operator toggle (RP1).** `KARST_RELAY_BLOB_PERSIST=durable|ephemeral` (`BlobPersistence`, fails
  closed on a typo, logged on start). `durable` (default) recovers parked blobs on restart (FT2
  above); `ephemeral` wipes them (`BlobStore::new`), the lower-residue posture. Either way the relay
  holds only opaque, capped, TTL-swept ciphertext — the toggle changes only HOW LONG encrypted
  bytes linger, never what the relay can read (nothing). This shifts the retention posture from the
  always-ephemeral mailbox model, so it is a knob, not a forced default.
- **Advertisement (RP2).** `RelayPolicy {blob_persistence, blob_ttl_secs, max_blob_size, pow_bits}`
  served over a public `GetPolicy` (Noise session, bounded, no cookie, no user info); `karst
  relay-info` prints it, tagging each field by how far a client can check it.
- **Preference + selection (RP3).** `RelayPrefs {prefer_persistence}` (per-account, sealed at rest);
  `karst relays --add` skips a verified relay whose advertised policy does not match. `karst
  relay-prefs` sets/shows it.
- **Proof-of-retrievability (RP4).** `verify_durability` fetches a random chunk of a parked blob back
  and checks it decrypts + authenticates at position (Filecoin/Storj-style audit). `blob_upload`
  runs it before returning the `FileRef`, so a relay that silently dropped the upload fails there.

**The honest asymmetry, stated everywhere in this arc (UI, docs, posts):** every policy field is
OPERATOR-DECLARED, and they differ in verifiability. PoW difficulty and the size cap a client
verifies by using the relay; **durable persistence is PROVABLE** (fetch a chunk back); but
**"ephemeral" is a claim no one can check remotely** — you cannot prove a party deleted / did not
copy data (canaries fail against selective retention; TEE attestation trusts a hardware vendor,
against our no-anchor ethos). Accountability for the unverifiable claim comes from the FUTURE
reputation layer, not crypto. Confidentiality never rested on ephemerality anyway: blobs are E2E
ciphertext + capped + TTL-swept regardless.

## Hardening pass, 2026-07-28 (what changed and what did not)

A full sweep of the external audit findings. Recorded here because several of them turned
out to be different from their description, and that is worth as much as the fixes.

**Closed.** Per-message and per-chunk AEAD derivation (a rolled-back ratchet or a reused
file key can no longer produce a two-time pad); at-rest sealing bound to (account, file,
state version); Argon2 raised to 128 MiB/t=3; one-time prekeys signed and their handout
put behind admission; bundle-slot creation metered with a 30-day TTL; per-class request
frame and admission ceilings; session table capped and drop-box mail routed to its owner;
deposits made idempotent; a failed relay's receive rolled back transactionally; unappliable
content parked before the ACK and replayed afterwards; accepts honoured only from a peer we
actually asked; container regions made crash-atomic; proxies destroyed rather than flagged.

**Closed since (live-pull amplification and unsolicited feed media).**

- **A `PostsRequest` no longer buys unbounded work.** One inbound control message used to load
  the whole (sealed) feed, spawn an OS thread and fire up to 30 separate publication sends, with
  no cooldown and no ceiling — a 1→30 amplifier repeatable by any stranger, able to drain the
  account's own 100-per-600s request quota and deny the *user* their sends. Replies now pass a
  global budget (`PostsReplyBudget`): at most 30 sends per 600 s in total across all peers, at
  most 2 reply jobs at once, admitted **before** the feed is read so a refused request costs a
  lock and nothing else. An admitted request is charged at least one unit even when the answer is
  empty, because the two sealed reads that discover "nothing to serve" are the real per-request
  cost, and an account with no public posts is the common case. The bound is global on purpose —
  a `PostsRequest` requires no contact status, so an attacker mints a fresh identity key per
  request and walks past anything keyed per-peer; per-peer state keyed by an attacker-chosen key
  is itself unbounded memory.
- **Unsolicited post media can no longer queue work.** A `PostAttachmentRef` was written straight
  into the durable pending-fetch queue for *any* sender who could open a session, and its `chunks`
  field — one blocking relay round trip each — was checked only for `!= 0` while the relay accepts
  a declared count up to 40 000. Refs are now admitted only from a **feed source** (the same
  consent the `Publication` itself needs) and only when `chunks == blob::chunk_count(size)`
  exactly, which caps an honest 96 KiB attachment at two 60 KiB chunks. The same shape check now
  covers `GalleryRef`, both download paths re-check defensively, and both assert the assembled
  length equals the declared `size`. The inline chunk path to the same sidecar
  (`PostImageManifest` / `PostAttachmentManifest`) got the identical feed gate — a gate on one of
  two routes to the same place is not a gate.

**Deliberately NOT fixed, and why — read these before trusting a property:**

- **Snapshot-diff against the Tier-2 container.** A cover-password write touches the same
  offsets whether or not a hidden compartment exists, and a hidden write's changed bytes
  fall inside the hidden region. An adversary holding two snapshots separates the
  compartments by offset alone. Masking would require rewriting the whole container on every
  save. See `docs/design/duress-tier2-container.md` — the earlier masking claim is retracted.
- **Whole-directory rollback.** The session file carries a generation and a separate anchor
  detects a PARTIAL rollback (one file restored from a backup). An adversary who restores
  everything, or deletes the anchor, is not caught: no purely local state survives an
  adversary who controls all local state.
- **Delivery, as opposed to storage.** A relay can now be run with DURABLE mailboxes
  (`KARST_RELAY_MAIL_PERSIST=durable`): every accepted message is fsynced to a mail log before
  the relay answers `Accepted`, and replayed on start, so an ordinary restart no longer loses
  queued mail. That is single-relay durability, not delivery reliability — if that relay's disk
  or the relay itself goes away, the message goes with it, and nothing replicates it (#149).
  The default stays `Volatile` (RAM only) because durability means opaque ciphertext lingering
  on the operator's disk, which is a posture to opt into, not inherit; the relay advertises
  which it runs (`RelayPolicy::mailbox_durability`) and a client can require a match
  (`RelayPrefs::prefer_mail_durability`). Deliberately **at-least-once**: deposits are fsynced,
  deletions are not, so a crash can redeliver a message the recipient already had — the client
  dedups by `payload_id`, and the alternative is an fsync on every fetch.
- **A withheld one-time prekey.** Signing stops substitution, not withholding, and refusing
  to talk would convert a downgrade into a lockout. The 3-DH case is reported
  (`ForwardSecrecy::NoOneTimePrekey`) and recorded per peer.
- **BlobGet request volume.** The size ratio is bounded (~437:1) and the transport rules out
  spoofed-source reflection, but request VOLUME rides the deliberately stateless cookie.
- **A batched `PostsPage` reply.** The audit asked for one bounded page instead of up to 30
  separate session messages. Not done: packets are camouflaged to a fixed 1400 B, so 30 posts do
  not fit one send anyway — it would buy a new content variant, a reassembly path and a
  receive-side fan-in in exchange for turning 30 sends into several. The budget above bounds the
  amplification per unit time regardless of how many posts exist, which is the stronger property
  for far less surface.
- **Live pull is deniable.** A flood can spend the reply window's budget and make this client stop
  answering profile views until it refills. That is the deliberate trade: losing "strangers can
  peek at my public posts right now" is recoverable, losing "I can send" is not.
- **`ChannelMigrate` re-points a contact's key without asking.** It is deliberately *not* behind
  SEC-29's outstanding-request ledger, and that is a category difference rather than an omission:
  the ledger answers "did we ask for this?", and a migration is an unsolicited notification from
  an already-authenticated contact, with no request to correlate — requiring a ledger entry would
  require one that can never exist. What does gate it is `migrate_contact_ik`'s own precondition
  (the sender must already be a contact) plus its refusal of a `new_ik` that belongs to a
  different contact. The residual is real and is elsewhere: nothing proves the sender holds
  `new_ik`, and the re-point is applied before the user sees it, so a compromised contact can
  silently redirect our future mail to a third party's key. `verified` is cleared and the UI
  prompts a re-verify, but after the fact. Closing it needs a staged migration (persist as
  pending, apply on explicit user action) — SEC-36's auto-redirect half, tracked separately.
- **A private account's posts still need a subscribe the recipient records.** `is_feed_source` is
  "a channel we subscribed to, or an author we pulled from"; a `JoinAccept { is_channel: false }`
  from an approving private account writes nothing, so its publications are dropped by the
  recipient. Pre-existing, and unchanged here — the new attachment gates deliberately match the
  `Publication` gate exactly rather than being wider or narrower than it.

**Cost the user pays.** Recovery-phrase restore brings back the root's network identity
only: never vault data, and — since proxies became destroyable — never the channels either.

## What the cold disk learns (at-rest audit, 2026-07-17)

Encrypted at rest (`Argon2id` → `XChaCha20-Poly1305`, see `client::secretbox`): the
root seed, account registry, contacts, history, reactions/edits metadata, profiles,
ratchet session state, capability, the network config (`net.dat`), the relay-selection
preference (`relay_prefs.dat`), and the discovery key (`discovery.key`, present only while
opt-in discovery is on).

**Received files are now encrypted too (FIXED).** They used to be written straight into
`received/` as ordinary plaintext under the sender's chosen name — a lost or stolen cold disk
handed over every file you were sent, content AND name, next to an encrypted history.
Now they are sealed under the vault key in `accounts/<id>/files/<random-id>.dat`
(`SealedFileWriter`): `u32 len ‖ MasterKey::seal(record)` records, the **file name is the
first sealed record** (the on-disk name is a random id, so a directory listing no longer
says "you were sent subpoena-response.pdf"), and the body is ≤64 KiB sealed chunks so a
multi-GB blob streams through with O(chunk) RAM. The blob download now seals **as it
streams**, which also closed the old `.part-*` window where a partial file sat in the
clear — there is no plaintext staging left on the receive path. It seals one record per
chunk (the alignment a resume counts on) but **fsyncs in ~2 MiB batches** (`seal` +
batched `sync`), not per 60 KiB chunk — ~30× fewer fsyncs on a large download, and a
resume tolerates the un-synced tail (truncate + re-fetch). And a **re-delivered inline
file dedups by its transfer id** (`save_received_file_deduped`, the inline analogue of
`blob_id` idempotency), so the mailbox re-delivering a small file before its ack saves +
surfaces it once, not twice.

**The honest cost, and the design answer:** an encrypted attachment cannot be opened by
an ordinary viewer. So plaintext exists only where the user explicitly puts it: a
received-file bubble has **"save as… (decrypts)"** → a native save dialog →
`Store::export_received_file` streams the decrypted bytes exactly there. The vault keeps
the copy; the exported one is the user's to manage. Tests: content, name, AND the
directory listing carry nothing readable (write it plaintext → reds; verified), and an
export round-trips byte-identical through a >2-chunk file.

**Named limits:** the container is not length-hiding (on-disk size ≈ file size, record
boundaries show the chunking) — it protects content and name, not the fact that a file of
roughly N bytes exists. The status bar now reads "🔒 history and received files are
encrypted on disk" — true again, and this time without a silent asterisk.

## The strongest design this discussion produced (2026-07-17)

> **Superseded on several points (later the same day) — read this first.** This is an
> earlier snapshot, before the network discussion settled. Where it disagrees with
> "Network shape: Public / Private nodes" (near the end of this file), **that section
> wins.** Specifically: (a) "a Private node must REFUSE open peering" is **moot** — federation (relay-to-relay
> forwarding) became a not-built fork and KARST is closed BY CONSTRUCTION, so there is no
> peering to refuse and a refuse-enum would guard a capability that isn't there;
> (b) "PIR only for the first knock" — PIR was since **measured as blocked** on an external
> wall (see the PIR section), and its remit grew to the epoch-chaining gap; (c) garlic
> bundling is listed here as "designed" but is **not started**. Kept as a dated record of
> the thinking, not the conclusion.

Every idea we examined — onion routing between our nodes, a federation of friends, a
stake, a directory, delegating to Tor — tried to buy privacy **with other people's
honesty**: hops that do not compare notes, an overlay that is not compromised, friends
who vouch truthfully and stay online. Each time, the bill came back priced by someone
else, and we either refused it (an authority, a token) or could not verify it
(non-collusion). That is the pattern, and it is the answer:

> **The strongest design is the one whose entire bill is payable in things we control:
> CPU, bandwidth, and our own code. Make the relay BLIND, rather than making the network
> complicated.**

### The design

1. **The relay is a hidden service on SEVERAL overlays at once** (`.onion` + `.i2p`,
   side by side, with failover between them). No IP to blackhole; no single network whose
   compromise is ours; and a Tor circuit to an onion service already IS client↔node onion
   routing — three hops each side, neither end knowing the other — so we ride it instead
   of rebuilding it. *(Dialing names: BUILT. The relay side needs no KARST code — point a
   hidden service at its port.)*
2. **Sealed openers.** The conversation opener stops naming the sender: encrypt the "it
   is me" to the recipient, so PQXDH still works and the relay reads nothing. *(Designed.)*
3. **Rotating drop-boxes.** The mailbox stops being your identity: derive its address per
   epoch from the secret the two parties already share. The relay sees a rotating
   random-looking address, not a person. *(Designed — the single biggest remaining win.)*
4. **Loop cover, Poisson delays, garlic bundling.** What survives 1–3 is timing and
   volume. Loopix's answer works on ONE relay: send yourself messages at a random rate so
   "is this user writing to anyone" has no answer — and vanished loops reveal that someone
   is dropping you. Store-and-forward already tolerates the delay. *(Designed.)*
5. **Node roles / federation** — reachability only, never described as privacy; a closed
   node must REFUSE open peering rather than warn (federation is transitive exposure).
   *(Designed.)*

### Why this is the strongest, stated as the argument and not the conclusion

- **Every cost is ours to pay.** CPU, bandwidth, code. Nothing waits on a stake, a
  directory, a token, volunteers, or a crowd we do not have.
- **It works at our actual size.** Onion routing needs a crowd to hide in; five users and
  three relays make correlation trivial no matter how many layers a packet wears. The
  blind-mailbox layers are *cheapest* exactly where an anonymity network is useless.
- **No layer is load-bearing for everything.** A fully compromised overlay still learns
  only "someone reached this relay" — not who, not whose mailbox: that is our payload. A
  hostile relay still never sees your IP: that is the carrier. Break either one and the
  other still holds. **That property is the whole point, and it is what betting on a
  single network would have thrown away.**
- **Sybil never has to be priced**, because we never select hops. We delegate that — and
  then diversify the delegation, so no one network is in a position to be our single
  point of failure.

### What it does NOT give — the same list, every time, unchanged by all this design

- An adversary who watches **both ends** defeats it. Every network on this page admits
  the same; we are not special.
- **The stranger's first knock** still needs one stable address to arrive at. That is the
  residual where PIR (or a dedicated contact-request channel) earns its keep — and it is
  the only place PIR is still needed once drop-boxes exist.
- Your relay still sees **volume and timing** against a rotating address. Cover traffic
  blunts this; it does not erase it.
- If every overlay is blocked and you hold no working route, **you are dark.** Out-of-band
  (a friend hands you an address) is the only rescue, and it needs no code.
- A **lost or stolen device** still reveals your contacts and who you verified. At-rest encryption
  protects the cold disk, not a running one you are logged into.
- **Drop-box deposit no longer implies fetch — WIRED LIVE.** The rotating drop-boxes now use
  Ristretto point-blinding (`node/src/blind.rs`): the recipient holds a per-account mailbox secret
  `m` and publishes `M = m·G` (in the bundle, and — for the responder direction — carried in the
  authenticated key-agreement); a sender computes the deposit address `h·M` from the PUBLIC `M`
  with no way to derive the fetch secret `h·m`, which only the recipient holds. The relay gates a
  fetch/ack with an in-group **Schnorr ownership proof** (`FetchOwnershipProof`) instead of the old
  `DH(mailbox_secret, relay)` for blinded boxes; the identity mailbox and the self loop-box keep the
  DH proof. So "can deposit" no longer confers "can read" — pinned by a discriminating test (the
  depositor, holding only `M`, is rejected at the fetch gate). The crypto is a REFERENCE
  construction (Schnorr is unaudited, and wants known-answer vectors before any production claim);
  design in [`design/mailbox-fetch-key-separation.md`](design/mailbox-fetch-key-separation.md).
  **BREAKING migration:** this changed the bundle (the prekey signature now covers `M`) and the
  fetch wire (`own_proof`). Bundles published before it fail signature verification and must be
  re-published; sessions established before it carry no `M` and **fail LOUD on the next send**
  ("re-establish this session") rather than silently dropping mail — reconnect to fix.
- **A fetch is always a lease; delete-on-read is gone (#179).** `FetchRequest` used to carry an
  `ack` flag, and with it clear the relay DESTROYED the served messages immediately — before the
  recipient had decrypted them, let alone written them down. The flag is removed, so no caller can
  select destructive reads and no default can be got wrong: every fetch leases, and a receiver that
  never ACKs costs a redelivery, not a loss. The skeleton `Recipient` (a reference receiver holding
  nothing durable) now ACKs on receipt, which is the honest moment for it; `Peer` still waits until
  the advanced ratchet is on disk. `Peer::enable_ack` survives but no longer selects the RELAY's
  behaviour — it only decides whether this receive records receipts to ACK later. Pinned by
  `a_fetch_can_no_longer_ask_the_relay_to_delete_on_read`, which asserts the message is STILL on the
  relay after being served (a second fetch coming back empty is true under both behaviours and would
  pin nothing) and that it redelivers once the lease lapses. Two follow-ups that the flag's removal
  made necessary rather than optional: `Peer` now records ACK receipts UNCONDITIONALLY (the old
  `enable_ack` opt-in made sense only while it also selected the relay's behaviour — with every
  fetch leasing, a receive that recorded nothing left mail on the relay with no receipt anywhere,
  the same "a signal exists that no caller consumes" shape this project has been caught by before);
  the receipts are bounded by `MAX_PENDING_ACKS`, dropping the oldest, whose leases lapse first
  anyway. And the reference `Recipient` acks ONLY the payloads it could actually open — an ACK says
  "the relay may forget this", and a `Payload::Session` envelope in its mailbox belongs to `Peer`.
  Pinned by `the_reference_receiver_only_acks_what_it_could_open`, discriminating on what SURVIVES
  on the relay.
- **Session receive is effectively-once, with one narrow residual loss.** The `recv_session` path now
  fetches under a **lease** and only tells the relay to delete a message (an ACK carrying the same
  ownership proof as the fetch) *after* the advanced ratchet is durably saved. A crash before the save
  redelivers the exact ciphertext once the lease expires (up to `LEASE_SECS`, so a fast restart is
  delayed, not lost); the ratchet's transactional decrypt fails closed on an already-consumed
  duplicate, so redelivery is effectively-once with no dedup store. The two former residual loss windows
  are now **closed** by persisting plaintext-first: `recv_session`/`recv_session_multi` write the
  decrypted text to history BEFORE the state commit or the ack (all under the sessions flock), and the
  burnt one-time prekey and the session derived from it commit **together, in one durable write**
  (`Store::save_receive_commit`, CRYPTO-26 — the prekey secrets now live INSIDE `sessions.dat`, so one
  rename commits the pair; `opks.dat` is gone and `STATE_VERSION` is 5). That last one was never a
  plaintext-loss window but an unrecoverable state one: two files meant a crash between them left
  "prekey burnt, no session", the unacked opener redelivered into an `accept_key_agreement` that no
  longer had the secret for the 4th DH term, and the sender kept ratcheting into a mailbox its contact
  could never open — manual forget/reconnect was the only way out. Swapping the write order would have
  traded it for a reuse window on a one-time secret, so the pair had to become one commit rather than a
  better order. Pinned by `a_crash_before_the_session_commit_leaves_the_prekey_to_reopen_the_contact`
  (drops the lease receipts, rolls the session file back, drives the relay clock past the lease, and
  requires the redelivered opener to still open). So a crash in `[session saved → history]` no longer
  loses the message — the plaintext is already durable, and a redelivered copy is skipped by a **payload_id**
  dedup over the recent history tail (collision-free, unlike a content hash, which would eat a genuine
  double-tap of the same text in the same second). Both single-homed (`recv_session`, CLI) and
  multi-homed (`recv_session_multi`, desktop/GUI) carry lease/ACK; the multi-homed path acks each leased
  message through the relay that leased it, only for relays whose receive succeeded. **Residual:** the
  text path is deduped by payload_id; **reactions and edits are idempotent under redelivery** (reactions
  use set semantics; edits are last-writer-by-`edit_ts`, so a stale/reordered edit never clobbers a newer
  one), making the crash-window duplicate a no-op for them. The remaining residual is **files**: a
  redelivered manifest/chunk in that window can still re-save once (→ the crash-safe blob slice).
  Disappearing messages (`TextExpiring`) are delivered live but never written to disk, by design.
- **Send now retransmits the exact ciphertext instead of losing it.** A message is encrypted (the
  ratchet advances unconditionally, saved before it can reach the wire so a duplicate can never reuse a
  message key) and queued in a durable **outbox** that lives IN `PeerState`, so it commits atomically
  with the ratchet snapshots — the invariant "envelope N queued ⟺ ratchet at ≥ N+1" needs both in one
  write. A transport failure keeps the exact bytes queued and `flush_outbox` retransmits them verbatim
  (FIFO) on the next send or poll — the old first-delivery-must-succeed gap is closed. **Deliverability
  bound:** the relay accepting a deposit is not the recipient decrypting it; a retransmit is decryptable
  only within the recipient's skipped-key window, which survives DH steps until `MAX_STORE` eviction
  (~2048 intervening messages), after which the deposit still succeeds but the recipient drops it (fails
  closed). Bounded by a wall-clock TTL + a queue cap, not by proof of delivery. Adding the outbox field
  is also the first concrete **format migration** (`PeerState::from_bytes_compat` loads a pre-outbox
  state file rather than bricking the ratchet) — backlog #6 (versioning) in the small.

### Order

Sealed openers → rotating drop-boxes → cover traffic + bundling → node roles / federation
(with unsafe combinations made impossible, not documented) → PIR only for the first knock,
if it is still wanted by then.

## The configuration model: everyone picks their own posture (2026-07-17)

Proposed as the product shape: every network available to both nodes and clients; the
USER decides, separately for their client and for their node. A maximal paranoid runs an
a closed node reachable only through protected networks; someone relaxed runs an open node that
federates easily, with clients auto-switching across SOCKS/HTTP/WebSocket; and a paranoid
can still reach a public, non-hiding node through Tor+VPN. **Audited: the shape is right,
most of it is already standing, and it has four traps — one of which is fatal to a combo
people will want.**

### What is already true

- **Client posture is already the user's, and already enforced.** The carrier is chosen,
  the allowlist derives from that choice and drops routes that would betray it, and
  failover + per-path health switch automatically among what is allowed. The "paranoid
  client → public node" case the proposal names **works today**: reaching a plain-IP relay
  over Tor needs nothing new.
- **Node posture is mostly configuration, not code.** A relay already listens on TCP and
  can terminate `wss`. **Becoming a `.onion` needs ZERO KARST code** — you point a Tor
  hidden service at the relay's port; the same for an I2P tunnel. The work is entirely on
  the CLIENT side (being able to dial a name), which is the gap named below.
- **Asymmetry is the good part.** The node operator's paranoia and the user's are
  independent variables, and neither has to match. That falls out of the design rather
  than needing to be built.

### The four traps

1. **FATAL to one combo: a closed node that federates is not closed.** Federation is
   transitive exposure — if a closed node peers with an open public node, its users'
   metadata reaches that node's operator, and its whole guarantee is gone. **The
   weakest peer defines the exposure of everyone who peers with it.** So "closed" and
   "federated with an open node" cannot both be true, and the config must refuse that
   combination rather than let an operator discover it later.
2. **Diversity of carriers and anonymity pull in OPPOSITE directions.** Many carriers
   defeat blocking; one big crowd defeats correlation. Split users across Tor, I2P and
   direct and every anonymity set shrinks. This is a real cost of "everyone chooses" and
   it is not fixable by configuration — only by naming it.
3. **The posture you pick is itself a signal.** If the only people on the I2P route in a
   country are the paranoid ones, "uses the paranoid mode" is the fingerprint. Being
   unusual is the leak; the safest posture is often the common one.
4. **A client's choice cannot protect what the RELAY learns.** Tor+VPN hides where you
   are; it cannot hide whose mailbox you drained — that is our payload. So "the user
   decides their own safety" is only true of their network position. The rest is the
   application-layer work (sealed openers, rotating drop-boxes), which no posture and no
   carrier substitutes for.

### What this implies for the config surface

Safe defaults, and the dangerous combinations made **impossible rather than merely
documented** — the allowlist already sets that precedent on the client. Node side needs
the same discipline: a closed (Private) mode that refuses open peering, not one that warns about
it.

## Not betting on Tor alone — carrier diversity (2026-07-17)

Objection raised, and it is correct enough to change an earlier conclusion of ours: this
document said "Sybil is DELEGATED to Tor", which is a bet on one organization. Audited
honestly, without conspiracy and without reassurance.

### Is Tor controlled? The honest read

- **The protocol is almost certainly not backdoored.** It is public, has twenty years of
  adversarial academic attention, and multiple implementations. A secret flaw surviving
  that is not the way to bet.
- **Leaning on one external network is a legitimate reason for caution.** Tor is a single
  network run by a single project, so treating it as your only layer concentrates trust in
  one place. The design treats it as one user-chosen route among several — not a foundation
  you have to trust on its own.
- **The network is not the protocol, and that is where the real risk lives.** The
  directory authorities are a handful of machines run by known people: a genuine
  centralization and a coercible one. And relay Sybils are not theoretical — large
  hostile relay groups (the "KAX17" reporting, ~2021) have run significant capacity.
- **Tor states its own ceiling**: it does not defend against an adversary who can observe
  both ends. Anyone who can watch enough backbone does not need to control Tor.

**Conclusion: "probably not backdoored" is not the same as "safe to be your only layer".**
The correct engineering response to that uncertainty is not faith in either direction —
it is **not depending on any single one**.

### Why "pick a better network" is the wrong fix

Every candidate has the same shape of problem or a worse one: I2P is smaller (less crowd
to hide in) though it has **no directory authorities** and needs **no exit** — which
makes it architecturally the *better* fit for our use (a relay is an in-network
destination, not a clearnet site). Lokinet buys Sybil resistance with a token (an
economy, and a state outbids you). Nym is a real mixnet (stronger against traffic
analysis than any onion router) and young, small, and token-based. Yggdrasil/cjdns give
encrypted addressing, not anonymity. **There is no network that is simply "better than
Tor" for us; there is only monoculture versus diversity.**

### The fix is structural, and we are one small gap away from it

**Tor, I2P and Lokinet all expose a SOCKS proxy, and all address by hostname**
(`.onion` / `.i2p` / `.loki`). We already have the carrier seam (`TransportAdapter`,
`Socks5Adapter`) and route lists with per-route carriers and failover. So the SAME gap
found in the previous audit — `Socks5Adapter` sends only ATYP `0x01`/`0x04`, never
`0x03` (domain name), and every route parses as a `SocketAddr` — **is what blocks all of
them at once**. Fixing it does not "add Tor support": it adds **any SOCKS-speaking
overlay**, and our existing allowlist + failover then lets one client carry
`.onion`, `.i2p` and direct routes side by side and switch between them when one dies.
**Diversity by construction, not by trusting anyone.** I2P deserves to land as a
first-class carrier alongside Tor, not "later" — precisely because its failure modes are
different ones.

### The deeper consequence: distrusting the network layer RAISES the priority of our own

If the carrier might be hostile, then the work no carrier can do for us matters more, not
less. Against a **fully controlled** overlay, sealed openers + rotating drop-boxes still
hold: the carrier learns "someone reached this relay", not who they are or whose mailbox
they drained — those are our payload, and no network operator can read them. Layers must
be independent, and **nothing may be load-bearing for everything**. That reprioritizes
the list: application-layer crypto first, carrier diversity second, and no single network
in a position where its compromise is our compromise.

**What carrier diversity does NOT fix, said plainly:** an adversary who watches both ends
(every overlay here says the same), and the relay itself — which is why the application
layer is the part that is ours to get right.

## What to steal from other networks (2026-07-17)

Surveyed I2P, Freenet, ZeroNet, GNUnet, Lokinet/Oxen, Nym, RetroShare. Filtered through
what we actually are: a store-and-forward mailbox on ONE relay, with the topology
problem delegated to Tor. **That filter matters — the instinct is to copy someone's
topology, and topology is the one thing we decided not to build.** The valuable steals
are the ones that work on a single relay, and they are the parts nobody copies.

### The best steal: loop cover traffic (Nym / Loopix)

Nym's token is not the interesting part; **Loopix's traffic discipline is**, and it works
with no network of our own:
- **Loop cover**: the client sends messages **to itself** through the relay at a random
  (Poisson) rate. A deposit then looks like every other deposit, so "is this user
  writing to anyone right now" stops having an answer. Our metadata audit named timing
  correlation as the ceiling that survives pseudonyms — **this is the thing that attacks
  it, and it needs one relay and no friends.**
- **It also detects active attacks**: your own loops are supposed to come back. Loops
  that vanish mean someone is dropping your traffic, and you can *notice* — nothing else
  in our design gives us that.
- **Poisson delays** rather than "send immediately": store-and-forward already tolerates
  latency, so we can pay for mixing with time we already have.
- **The trap, named**: cover traffic that is DISTINGUISHABLE from real traffic is worse
  than none — it advertises "this client runs cover". Loopix's loops are real messages
  over the real path, which is exactly why they work. Cost is honest: bandwidth and
  battery, always, forever.

### Second: garlic bundling (I2P)

I2P wraps several messages ("cloves") into one encrypted packet. For us: batch multiple
deposits (and the fetch) into a single relay request. Fewer round trips, and — the real
prize — **fewer distinguishable timing events for a correlator to line up**. It composes
with cover traffic and needs nothing but our own wire format. I2P's other ideas
(unidirectional in/out tunnels breaking correlation symmetry; subjective peer profiling
instead of a global consensus) are good but presuppose the network we are not building.

### Third: GNS-style petnames and zone delegation (GNUnet)

GNUnet's Name System answers a question we have open — **naming and discovery without a
global list** — by giving each user a zone and letting them *delegate* to contacts'
zones (your friend's "bob" resolves through their zone, not a global registry). That maps
onto our §12 tiers and our contact graph, and it is a real answer to the residual we
keep hitting: **the stranger's first knock** and relay discovery. Petnames also solve a
UX problem honestly (human names that are local and personal, never globally unique — so
no namespace to squat or take over).

### Fourth, with a real bill: swarms (Lokinet/Oxen/Session)

Their messenger stores a user's offline messages redundantly across a **swarm** of nodes
rather than one. Our mailbox lives on exactly one relay: take it down and the mailbox is
gone. Replication would fix availability — **and multiply metadata exposure by n**, since
every swarm member sees the same deposits. That is a genuine tradeoff, not a free win,
and it needs a node registry (theirs is a blockchain; we reject the token). Park it.

### Friend-relayed transport and discovery-through-friends (RetroShare, Freenet darknet)

Both build the network out of authenticated friends: your traffic tunnels through people
you know, and you learn about others' addresses through them. We already took the small
end of this — contact route sharing shipped this session, with explicit consent both
ways. The large end (your friend's node relays for you) is the social-graph option
already priced above: it works, and its bill is that your first hop knows you.

### Freenet's other real contribution: operator deniability

A Freenet node stores encrypted chunks it cannot read or index — so the operator can
honestly say they do not know what they hold. **We already have this property and never
say it**: our blob store holds E2E ciphertext with a key the relay never sees, so a relay
operator cannot know what is on their disk. Worth stating plainly in the relay operator's
documentation — it is a fact about our design and it matters to whoever runs one.

### ZeroNet: little, and it is worth saying so

BitTorrent-style sites keyed by a signature, served by their readers. The one
transferable idea — the reader becomes a server — is a peer-to-peer topology for public
content, which is not what a private messenger is. Its anonymity depended on being run
over Tor anyway, and the project is effectively dormant. **No steal here; manufacturing a
lesson from it would be padding.**

### Ranked, for us

1. **Loop cover traffic + Poisson delays** — attacks the exact ceiling our own audit
   found, on one relay, no network, no friends, no token. The best idea on this page.
2. **Garlic bundling** — cheap, composes with (1), fewer events to correlate.
3. **GNS-style petnames/zone delegation** — the honest answer to naming and the
   stranger's-first-knock residual.
4. **Operator deniability** — already true; say it.
5. **Swarms** — real availability win, real n× metadata cost, needs a registry. Later.
6. **ZeroNet** — nothing.

**The pattern worth noticing:** every network on this list pays for anonymity with a
token, a DHT bootstrap, or a friend graph — all three of which we have already priced and
declined. What is left when you strip the topology is **traffic discipline** (cover,
delays, bundling), and it is transferable precisely because it does not need anyone
else's cooperation.

## Combining the layers — what each one actually adds (2026-07-17)

Corrections accepted, and one of them breaks an earlier conclusion of ours: a VPN can be
**your own** (so "a company that sees everything" was sloppy); onions can run
client↔node as well as node↔node; and a node can live entirely as a Tor site. Evaluating
the stack honestly produces a smaller answer than expected — and makes our biggest
planned item redundant.

**The rule that organizes everything below:** a carrier can only hide *where you are*.
It can never hide *who the mailbox belongs to* — that is written in our own payload and
no amount of tunnelling touches it. So the stack splits cleanly, and each layer must be
judged only on the question it can actually answer.

### What each layer adds, and what it cannot

| Layer | Adds | Cannot |
|---|---|---|
| **Client → relay over Tor** | Relay never learns your IP; the observer sees Tor, not KARST | Anything about the mailbox — the relay still reads whose it is |
| **Relay AS a Tor onion service** | **An onion-service endpoint reached through Tor; the operator's network location is not exposed as a routable IP.** Also: client↔node onion routing, already built, for free — a Tor circuit to an onion service IS client-applied onion layers (3 hops each side, neither end knowing the other) | Same: the application layer is untouched |
| **Sealed openers + rotating drop-boxes** | Kills the mailbox↔identity link and the sender's identity on the wire — **the only layer that removes relay-side metadata** | Nothing about blocking or your IP |
| **Node ↔ node onion / federation** | Reachability across separate relays; operators do not learn each other's IPs; a compromised relay's peer list is `.onion` addresses, not locations (this materially softens the "compromise one relay → map of the operators" objection above) | **Nothing for user metadata** — your own relay still watched you deposit |
| **Your own VPN (WireGuard)** | A **personal bridge**: a way to reach Tor or the relay when a direct path is unavailable. And the relay sees your VPS, not your home line | Anonymity: the VPS is rented by you, paid by you, and is one subpoena from being you. WireGuard is also trivially visible to traffic classification, so as a transport it needs obfuscation |

### The combination that matters — and it is not the ambitious one

**Relay as a `.onion` + client over Tor + sealed openers + rotating drop-boxes.**

Walk what a hostile relay holds under that stack: no IP (Tor), no sender identity (sealed
openers), no recipient identity (the mailbox is a rotating address derived from a secret
it does not have), and no way to link fetches to deposits by address or by IP. What is
left is volume and timing against a rotating address. **That is Principle 5 against a
single relay — with no federation, no onion network of our own, no Sybil price, and no
token.**

And it inverts an earlier conclusion of ours honestly: we said PIR might buy more than an
onion network. With rotating drop-boxes, PIR is no longer needed for ordinary
conversations at all — it shrinks to one residual, **the stranger's first knock**, which
still needs a stable address to arrive at.

### What that means for the ambitious items

- **Our own onion network between nodes: redundant for user privacy.** Once the four
  layers above are in place, node↔node onion adds nothing a user can feel. It remains
  worth having for *reachability* and *operator safety* — and must be sold as exactly
  that.
- **Sybil: not solved — delegated to whichever overlay the user picks.** We stop needing
  to price non-collusion because we no longer select hops; the overlay does. But
  delegating to ONE overlay is a bet on one organization — see "Not betting on Tor alone"
  below. We inherit the chosen network's threat model wholesale, including its limits (no
  defence against an adversary watching both ends — every candidate says this) and its
  dependency: if it is blocked or compromised, we fall back. The answer is carrier
  DIVERSITY plus application-layer crypto that survives a hostile carrier — not faith in
  any one network.
- **Federation modes stay worth building** — for closed nodes to reach each other, not for
  anonymity.

### Order this implies

1. **Dial `.onion` at all** (the two-line-ish gap: SOCKS5 ATYP `0x03` + hostname routes).
   Nothing else in this list is reachable without it, and it alone converts "the relay IP
   is a fixed blockable endpoint" into "the relay has no IP".
2. **Sealed openers**, then **rotating drop-boxes** — the only work no carrier can do for
   us.
3. **Federation by private peering over `.onion`** — reachability, honestly labelled.
4. **PIR** — only for the stranger's-first-knock residual, if we still want it then.
5. **Own VPN**: document it as a personal bridge for reaching the relay when a direct path is unavailable. Not privacy.

## Node roles + federation + relay-to-relay transport — design audit (2026-07-17)

> **Superseded wording.** This and the other dated design-audit sections above predate the
> settled design; the forward-looking "Network shape: Public / Private nodes" near the end
> of this file wins where they disagree. Left as a dated record of the thinking, not the
> conclusion.

Proposed: let a node be configured as closed OR as part of a network; connect chosen
closed nodes to each other without joining any global network; carry relay-to-relay links
over onion routing, a VPN, or maybe I2P. Audited. **The idea is largely right, it
contains one trap that must not be shipped as a feature, and auditing it turned up a
concrete gap worth more than the rest.**

### It is two independent knobs. Conflating them is the trap

| Knob | Question it answers | What it can never do |
|---|---|---|
| **Federation policy** (closed / chosen peers / open) | WHO is in your network — trust and reachability | Change what a relay learns about its own users |
| **Relay-to-relay transport** (Tor / I2P / VPN / plain) | HOW the link between relays looks to an outsider | Give your USERS anonymity (see the trap below) |

### Knob 1 — the modes

**A closed posture is not a bug; it is the strongest posture available, and it is what we
accidentally already are.** Membership is out-of-band, there is no foreign traffic, and
nothing peers with strangers. It does NOT reduce what the relay learns (the metadata
audit above stands in full) — it changes WHO that knowing party is: from "an untrusted
stranger" to "someone you or your community chose". That is a coherent, honest model and
deserves to be a named, supported mode rather than an unspoken default.

**Private federation (peer only with relays you chose) is the strong idea here, and the
reason is worth spelling out: it sidesteps Sybil instead of solving it.** The earlier
audit killed onion routing because Sybil resistance cannot be bought at a price we accept
— but Sybil only bites when membership is **open**, i.e. when hops are picked from a pool
of strangers anyone can join. If every hop is a relay whose operator you deliberately
peered with, there is no open market to flood. The scarce resource becomes "an operator
I decided to trust", which an adversary cannot mint. **This is the one construction that
makes onion routing conceptually available to us.**

Its bill, which must be read aloud:
- **A federation of friends is easier to collude, not harder.** Tor's real strength is
  that its operators are strangers with unaligned incentives and no way to coordinate
  quietly. Yours would be friends who talk to each other daily.
- **It is discoverable.** Compromise one relay and you get its peer list *and* the social
  relationships behind it. That is a map of the operators, which is exactly what a state
  wants — the federation's structure is itself sensitive.
- **Anonymity is bounded by the federation's size and diversity.** Three relays run by
  three friends in one jurisdiction give the appearance of onion routing and none of the
  substance.

**Open network:** needs the Sybil price we cannot pay. Don't.

### Knob 2 — the trap, stated plainly

**Carrying relay↔relay links over Tor/I2P/VPN protects the RELAYS, not the USERS.** If
Alice's relay forwards her message to Bob's relay through Tor, Alice's relay still saw
"Alice → Bob's mailbox" with its own eyes. The users gained exactly nothing. Only onion
layers applied by **Alice's client** (wrapping for hop1→hop2→hop3, so her own relay
cannot read the destination) buy user anonymity. Transport privacy between relays is
about operator safety and blocking resistance — real, but a different product. Shipping
it and letting it be read as user anonymity would be the same overclaim this project has
already caught twice.

### What federation honestly buys (state this, and only this)

- Today, one relay knows *(your IP, who you write to)*.
- Federated, **your** relay knows *(your IP, who you write to)*; **their** relay learns
  *(its own user, "this came from relay A")* — and NOT your IP.
- So the recipient's relay learns less about you; your own relay still knows everything.
  That is the e-mail/Matrix model: your server is your trusted party. Coherent and
  honest — just not anonymity. Removing your own relay's knowledge needs client-side
  onion layers, which lands back on knob 1 with 3+ hops and non-collusion among peers you
  chose.

### On the transports specifically

- **VPN: a company that sees everything and can be leaned on.** It hides the link from
  your ISP. It is a carrier, not privacy, and must never be listed beside Tor/I2P as
  though it were the same kind of thing.
- **Tor vs I2P — both give the property that actually matters here: a relay with NO
  blockable IP** (onion service / I2P destination). Tor: larger anonymity set, far more
  scrutiny, onion services well-trodden; we already speak its SOCKS port. I2P: built for
  in-network destinations (garlic routing), needs no exit, fully P2P — conceptually the
  better fit for relay↔relay, but smaller and less examined. Pragmatic order: Tor first,
  I2P as a second carrier later (it also speaks SOCKS, so the seam is the same).

### The concrete gap this audit found — NOW FIXED

**A relay published as a Tor onion service exposes no routable IP to blackhole and does not reveal its
operator's network location** — worth more for endpoint availability than any onion-network design in
this document. We could not dial one at all: `Socks5Adapter` only ever sent ATYP `0x01`/
`0x04`, and every route parsed as a `SocketAddr` so names were silently dropped.

Both are fixed. `Dest` (host + port, where host may be a NAME) replaces `SocketAddr`
through the path list; `Socks5Adapter` sends **ATYP `0x03`** so the PROXY resolves the
name — the only thing that can resolve `.onion`/`.i2p` — which also keeps an ordinary
hostname's lookup inside the tunnel instead of leaking it to local DNS. `DirectTcpAdapter`
**refuses** a name loudly rather than resolving it (a `.onion` has no DNS answer, and
quietly resolving a hostname would hand the lookup to a resolver the user never chose).

**This unlocks every SOCKS-speaking overlay at once, not just Tor** — `.i2p`, `.loki` and
anything else that speaks SOCKS and addresses by name — and the existing allowlist +
failover then carry `.onion`, `.i2p` and direct routes side by side, switching when one
dies. Carrier diversity by construction (see "Not betting on Tor alone").

**The relay side needs no KARST code at all**: point a Tor hidden service (or an I2P
tunnel) at the relay's port and hand out the name as a route.

Tests: a SOCKS CONNECT to a `.onion` really goes out as ATYP `0x03` with the name and
port intact (a mock proxy reads the bytes off the wire — this cannot pass by accident,
since the old code could not express a name at all); direct refuses a name instead of
resolving it; `Dest` parses names, IPv6 literals and rejects junk; and a `.onion` route
survives parsing, the allowlist and path assembly under a Tor user. The old test
asserting hostnames are DROPPED was updated — it pinned the contract this change
deliberately reverses.

## Sybil, and whether cryptography can solve it — design audit (2026-07-17)

Asked to look wider (anonymous decentralized networks) and specifically whether there is
a **cryptographic** way out. Researched against our own spec first, since it already
made choices nobody had priced.

### The short answer: no, and that is a result, not an opinion

Douceur's 2002 Sybil result: without a trusted authority, identities are free to mint
unless creating one **costs a scarce resource**. Cryptography can *enforce* a cost, *spend*
it unlinkably, or *prove* it was paid — it cannot **manufacture scarcity**. So "solve
Sybil with crypto" is not a design option; the real question is:

> **which scarcity are we willing to depend on?**

Every anonymous network answers exactly that, and each answer is a bill:

| Scarcity | Who does it | What it costs you |
|---|---|---|
| **A trusted authority** | Tor (directory authorities vote the consensus); Katzenpost/Loopix (PKI) | A single point of control — our independent-relays principle says no. And it is not even sufficient: large relay Sybils have gotten into Tor anyway |
| **Money / stake** | Nym, Oxen/Lokinet (token + staking) | Prices a Sybil honestly — and requires a token economy: traceable, contradicts "non-commercial", and a well-funded adversary simply buys in |
| **Computation (PoW)** | Hashcash-style admission | Linear cost. A well-resourced adversary does not notice it. Buys minutes against a casual attacker |
| **A human willing to vouch** | Freenet darknet, Briar, SSB (the social graph IS the topology); SybilGuard/SybilLimit bound accepted Sybils by the number of "attack edges" | The only non-commercial, non-authority scarcity — and it means your first hop is your friend, who therefore knows you are online and sending |
| **Observable resource diversity** | Tor (bandwidth weighting + ASN/family limits); **our §11** | Prices a Sybil at "a few accounts across ASNs", not at "a well-resourced adversary cannot" |
| **Subjective peer profiling** | I2P (each router measures peers itself; no global list to poison) | No authority and nothing to poison centrally — but a Sybil that actually performs still gets selected |

### What KARST already chose — and the hole in it

Our spec is not silent, and that is worth saying: **§11** picks *observable resource
diversity* (different ASN, /24, operator, jurisdiction, issuer class, availability
history, **measured** — not claimed — throughput) plus route-concentration limits and
**client-side route selection from several independent descriptor sources** (the relay
never proposes the next hop). **§12** distributes descriptors in tiers — public relays,
limited-distribution via the social graph with short TTLs, and a private per-contact
capability. **§19** answers the incentive with *transitive credit along the trust graph*
(Sphinx `CreditOnion`), not a token.

That is a coherent, token-free, authority-free design. The audit finding is what it
actually prices:
- **IP / /24 / ASN / jurisdiction are client-verifiable** — they fall out of the
  descriptor's address. (Dependency nobody has shipped: an IP→ASN dataset, kept fresh.)
- **"Different operators" and "issuer class" are SELF-DECLARED** — an attacker declares
  ten operators. Unenforceable as written.
- **"Measured, not claimed, throughput" needs a measurer.** Tor needs trusted bandwidth
  authorities for exactly this — and authorities are what we refused. The only
  authority-free option is I2P-style *subjective* measurement: each client trusts what it
  measured itself, which is slow, local, and only covers relays it already used.

So §11's honest price for a Sybil today is **"a handful of VMs in different ASNs"**. That
is a real cost, and it is nowhere near a state. Written down, not implied.

### Where cryptography genuinely buys something (and where it does not)

- **Sphinx** (already in §19.2) — the onion packet format. Solves *layering*, not Sybil.
- **VRF path selection** — stops an adversary from *choosing* to sit on your path; raises
  the cost of a **targeted** Sybil. Does not stop a **blanket** one.
- **RLN / blind credentials** — let you spend a scarcity without linking your uses.
  **Note the distinction our own docs blur: RLN is CLIENT rate limiting, not RELAY Sybil
  resistance.** It answers "how many messages may an anonymous user send", never "who may
  run a relay".
- **PIR (Private Information Retrieval) — the one that fixes a leak this audit found.**
  Our fetch names you (`mailbox` = your IK), and that is precisely what lets a relay
  correlate pseudonymous deposits back to an identity. PIR lets you retrieve your mailbox
  **without the relay learning which mailbox**. Cost, honestly: single-server PIR is
  computationally heavy (work linear in the mailbox count per query); multi-server PIR is
  cheap but assumes **non-colluding** servers — which walks straight back into Sybil.
- **Not a solution: TEE attestation** — trusting Intel/AMD is a coercible authority
  wearing a silicon hat.

### Reasoning it through to something we can actually build

**Step 1 — name the goal in one sentence.** We want no single party to learn "X is
talking to Y". Today our relay learns it outright.

**Step 2 — there are only two ways to get that, and they are not variations of each
other.**
- **Split the knowledge across several parties.** Each hop learns one piece: the first
  knows you but not your correspondent, the last knows your correspondent but not you.
  That is onion routing. It works *only if those parties do not compare notes.*
- **Blind the single party with mathematics.** One server sees every request and still
  cannot tell what it just served, because it is computing on data it cannot read. That
  is what Private Information Retrieval (PIR) does: the server does work across *all*
  mailboxes and hands back something only your key turns into *your* mailbox — it never
  learns which one you asked for.

**Step 3 — the first way has a price we cannot pay.** "They do not collude" is not
something you can check; you can only make *being many parties* expensive. That is the
Sybil problem, and per the table above, cryptography cannot create the scarcity — you
must buy it with an authority (refused: Principle 3), money (refused: non-commercial,
and a well-resourced adversary simply buys in), or human vouching (then your first hop is your friend, and
our own §19.2 admits 1–2 hops are worth nothing — you need 3+ friends-of-friends running
relays and online). Our §11 answer prices a Sybil at a few VMs across ASNs. **So a KARST
onion network is a bet on strangers at a price we do not set.**

**Step 4 — the second way's price is CPU, which we can simply pay.** No federation, no
stake, no directory, no volunteers. And note the cost curves run OPPOSITE ways:
PIR costs work proportional to the number of mailboxes, so it is **cheapest on a small
network** — exactly where an onion network is useless because there is no crowd to hide
in. Onion routing only starts working at a scale we do not have. **PIR is the tool for
the size we actually are.** (Its honest limit: it stops being cheap as we grow.)

**Step 5 — and much of the "anonymity network" work is already done by someone else.**
We support routing through Tor as a carrier. Tor already bought volume and
non-collusion as well as anyone ever has. **Building our own three-relay onion is
strictly worse than riding theirs.** But Tor hides your *IP* — it cannot hide that the
mailbox you drain is named after you. That part is ours alone, and no carrier fixes it.

So the division of labour is clean:
| Layer | Question | Who answers |
|---|---|---|
| Network | "who is connecting, from where" | **Tor, already wired.** Do not rebuild |
| Application | "whose mailbox is this, who deposited" | **Only our own crypto.** No carrier can |

### What will actually help us, in order

1. **Seal the opener.** Today a new conversation carries your identity key in the
   payload for the relay to read. Encrypt that "it is me" part to the recipient. Removes
   the last plaintext identity on the sending side. Self-contained; no new dependency.
2. **Stop naming the mailbox after the person — rotate drop-boxes.** The deeper fix, and
   cheaper than PIR: derive the mailbox address from the secret Alice and Bob already
   share (per epoch), instead of "your identity, forever". Both sides can compute it;
   the relay sees a rotating random-looking address it cannot tie to anyone. Cost: you
   fetch one address per contact per epoch (work linear in your CONTACTS, not in the
   whole server), the ownership proof moves from "I own this identity key" to "I know
   this shared secret", and a stranger opening a conversation still needs one stable
   address to knock on — that residual is where PIR (or a separate contact-request
   channel) earns its keep.
3. **Ride Tor by default, not as an option.** The carrier exists. Making it the
   recommended path buys network-layer anonymity we would otherwise spend years failing
   to rebuild.
4. **Fetch on a schedule with cover.** Cheap partial defence against timing correlation:
   poll whether or not you have mail, so "activity" stops implying "has traffic". We
   already jitter the cadence; this is the next honest increment, and it is small.
5. **Federate by static peering — for REACHABILITY, never for anonymity.** It turns
   separate relays into a network so people on different relays can talk. It claims nothing
   about privacy, and must never be described as if it did.

**And what not to build:** our own onion network (a bet on strangers), a token/stake
(an economy, and a state outbids you), directory authorities (the coercible point we
exist to avoid).

## Onion routing between relays — design audit (2026-07-17)

Asked: could we onion-route between our own nodes, and how would relays learn about
each other? Audited against the code rather than the vibe. Short answer: it is the right
direction and the only thing that delivers Principle 5 — and building it now would be
anonymity theater. Both halves are load-bearing.

**Precondition nobody wrote down: KARST is separate relays, not a network.** `Peer::connect`
fetches the recipient's bundle from `self.transport` — the sender's OWN relay. So both
parties must publish on the SAME relay to talk at all, and a relay has ZERO notion that
another relay exists (no peering, no gossip, no addressing — grep finds nothing). Every
deployment is a closed node. That is a structural limit and it was not documented until
now.

**Why the idea is right.** The mailbox model maps onto onion routing better than Tor's
interactive circuits do: the entry hop would see your IP but not the recipient; the
mailbox-holding hop sees the recipient but not you. That IS "no single intermediary
learns both ends". And store-and-forward tolerates latency, so real mixing (batching,
delays) is available — Tor cannot do that without breaking browsing.

**Why not yet — three gates, two of which are walls we already own:**
1. **No substrate.** Relays cannot address, authenticate or reach each other, and a
   capsule for IK_B must find the relay holding B's mailbox — that is the §12 directory
   problem again, now for relays instead of endpoints.
2. **No Sybil cost — this is the disqualifier.** Onion anonymity assumes the hops do not
   collude. Anyone can run a KARST relay for free, so an adversary runs most of them,
   sits on both ends of your circuit, and you have paid latency for a privacy claim you
   do not have. Our own spec names the answer ("a stake per node — the price of Sybil"),
   and the layer where it would live is exactly the one that is stubbed: the RLN zk
   membership circuit, with a public forgeable dev-capability standing in. **Onion
   routing on top of a Sybil free-for-all is worse than no onion routing, because it
   invites the claim.**
3. **Anonymity loves company.** Three relays and five users: correlation is trivial no
   matter how many layers the packet has. Tor's anonymity comes from volume; the math
   only distributes it.

**What it costs even done right** (so nobody prices it as "just add layers"): per-hop
admission — our cookie/capability is per-relay, and one capability presented at three
hops LINKS them unless it is blinded per hop; per-hop replay state; path selection
without a directory; and the operator-incentive problem the spec answers with §19's
CreditOnion, i.e. an economy.

**Honest sequencing.** Federation first — let people on different relays talk. It is
valuable on its own (separate relays → network), it is the substrate onion routing needs, and it
claims nothing about anonymity. Then a Sybil cost. Only then onion routing, which can
finally mean what it says. Doing it in the other order repeats the mistake this audit
already caught once: shipping a mechanism whose main effect is licensing a claim.

**How relays would learn about each other** (the second question, same honesty applied):
static peer config (what Tor's directory authorities effectively were at the start) is
the only option that needs no new trust and no new wall — an operator lists peers, done.
Gossip needs a bootstrap, which is the blockable thing. And a public relay list is
enumerable by an adversary BY DESIGN (clients need it too) — Tor accepts that and answers
with bridges. None of this is built; the first honest step is static peering, not
discovery.

## What the relay learns (metadata audit, 2026-07-17)

The relay is UNTRUSTED for content (Noise + E2E) — but "untrusted" is not "blind", and
what it sees was never written down. Field by field, as implemented:

> **Direction (in progress, not yet reflected below):** the `mailbox = your IK` and
> `publish = your IK + bundle` rows are the last places your *permanent* identity meets the
> relay. The [proxy-identity model](design/proxy-identity.md) removes the permanent identity
> from the wire entirely: the mailbox and bundle a relay sees belong to a **disposable proxy**
> (an HD-derived, rotatable channel), never to a root identity — the root has no address. The
> "stranger's first knock needs one stable address" constraint stays, but that address becomes
> a burnable proxy you can rotate, not the identity your contacts know. It also lets the relay
> cluster *your own proxies* by fetch behaviour unless each rides its own circuit — a new,
> honestly-stated limit. This table still describes the single-IK behaviour that ships today.

| Path | The relay reads | Consequence |
|---|---|---|
| Deposit (`WireMessage`) | `recipient` = **a rotating per-session drop-box** for everything after the opener (was the recipient's IK — FIXED), `client_addr` = **a random per-purpose, per-epoch handle** (was the sender's IK, then a per-process pseudonym — FIXED), `request_nonce` = **32 random bytes** (was IK ‖ counter — FIXED), `carrier_id`, cookie, capability proof, ciphertext length, arrival time | The relay reads neither party's KARST identity off a delivered message, and cannot count messages per identity. It still learns your IP + timing, and the deposit/fetch pair on one box is inherently linked — it IS the drop-box. See the drop-box section below for what rotation does and does not buy |
| Conversation opener (`SessionEnvelope::InitialSealed`) | a fresh ephemeral pubkey + ciphertext — **no sender identity** (was `KeyAgreement.ik_a_pub` in the clear — FIXED) | The whole `KeyAgreement` now rides in a sealed box addressed to the RECIPIENT's IK (`seal::SkeletonSeal`: ephemeral X25519 → their key, HKDF → ChaCha20-Poly1305). The recipient opens it without knowing who sent it, then runs PQXDH as before, so sender AUTHENTICATION is unchanged — it was never the relay's business. Guarded by a byte scan of the WHOLE envelope, not a field check |
| Fetch — identity mailbox | `mailbox` = your IK, `client_addr` = a handle used ONLY for this, your IP, timing | Which identity is online, from where, and when. Inherent while a stranger's first knock needs one stable address to arrive at. It gets its own handle so it does not relink the drop-boxes polled beside it |
| Fetch — drop-box | `mailbox` = a rotating box, `client_addr` = a handle that rotates with it, your IP, timing | Names nobody by itself. But the box is re-polled across each epoch boundary (skew tolerance), which lets a relay that LOGS fetches chain epochs together — the gap pinned below |
| Publish (§12) | your IK + your bundle | Inherent: the relay hosts your bundle so others can open a conversation |
| Blob (§15) | `client_addr` = **a per-session pseudonym** on both put and get (was uploader's/downloader's IK — FIXED), the same random `blob_id` on both | The two ends are no longer linked BY IDENTITY; `blob_id` still links the two transfers to each other, and sizes/timing/IP still leak. The blob store uses the pseudonym as an opaque owner handle (first-writer-wins + per-sender caps) — those caps were already best-effort with a forgeable self-declared sender, so nothing that held is weakened |
| Every path | your IP (it terminates your TCP), unless you ride an external PT | The network-layer identifier the carrier layer exists to hide |

**The honest answer to "what does the server know about me": your IP, your sizes and
timing, who you are whenever you poll for openers, and — if it keeps logs — which
rotating boxes belong to one conversation over time.** What it no longer gets for free
is either party's identity on a delivered message, or the recipient's identity on the
address it was sent to.
Principle 5 ("no single intermediary learns both source and destination") remains a
GOAL, not a description of this build — the README says so.

**What was fixed and what was not.** The transport-level leak was gratuitous, so it is
gone: `client_addr` is used ONLY for cookie issue/verify (the quota rides the capability,
the replay filter rides the nonce — verified), and the nonce's IK prefix bought only
cross-peer uniqueness, which 32 random bytes give too. Both are now a per-session
pseudonym / random bytes: fresh `OsRng`, never derived from the IK (a derived handle
would be a stable per-IK label the relay reverses by correlating with your fetch).
Guarded by `a_deposit_does_not_carry_the_senders_identity_in_the_transport_fields`
(restore the IK in either field → reds; verified).

That single per-process pseudonym was superseded by slice 2 — see below. It was enough
to stop the relay reading identities off a deposit, and NOT enough once addresses
started rotating, because one stable handle across every path relinks everything it
touches.

**The opener is now sealed (plan slice 1).** `KeyAgreement.ik_a_pub` was not gratuitous
— PQXDH needs it — so it could not simply be dropped; it is now wrapped in an outer box
addressed to the recipient (`SessionEnvelope::InitialSealed`), reusing `seal::SkeletonSeal`
with no new crypto. That primitive's *lack* of sender authentication — the flaw that made
it unfit as an E2E layer — is exactly the property wanted here: anyone can seal to you,
and only the inner PQXDH says who it really was. The test that used to assert the leak
EXISTS was inverted rather than deleted, and now scans the WHOLE envelope for the
sender's IK (a field check is what "moved the leak to another field" would pass).

**Honest scope:** this removes the SENDER from the opener. The recipient's mailbox is
still named on the opener itself (slice 2 fixed every message AFTER it — see below), and
the fetch-names-you correlation ceiling is unchanged. **PQ posture, named deliberately:** the outer box is ephemeral-X25519 → the
recipient's IK, i.e. classically sealed. Content stays post-quantum, but a future quantum
adversary who RECORDED an opener could recover the edge. A hybrid outer box would need a
second ML-KEM ciphertext (~1088 B) and does not fit the packet ceiling; the path to one
without extra bytes (move the existing `kem_ct` outside the seal and reuse its secret with
domain separation) is real but is new crypto composition and needs review. Recorded here
rather than discovered later.

## Rotating drop-boxes (plan slice 2, 2026-07-17)

> **P0 fix (audit, 2026-07-17): the drop-box is now DIRECTIONAL.** As first shipped a box
> was derived from `(seed, epoch)` with no direction, so A→B and B→A shared ONE address.
> Two P0 consequences: the sender could fetch — and, polling before the recipient, DRAIN —
> its own outbound mail; and the relay watched four operations on one address instead of
> two. Fixed: the box binds a direction byte chosen by ordering the two identity keys
> (symmetric, exchange-free), so each party deposits into `(me→peer)` and fetches
> `(peer→me)` — different boxes. Pinned by
> `the_sender_does_not_drain_its_own_outbound_before_the_recipient_fetches` and
> `the_two_directions_of_a_session_are_different_boxes`.

**What was wrong.** Every message went to a mailbox addressed by the recipient's
long-term identity key — the same key published in their bundle so strangers can find
them. Anyone who could look you up could therefore watch mail arrive for you. The
address was your name, in public, forever.

**What made the fix possible.** The relay never required the mailbox to be your identity
key. A mailbox address is an X25519 public key and `handle_fetch` grants a drain to
whoever proves they hold the secret (`DH(relay_identity, mailbox)`) — the check is
against the address itself and does not care where the key came from. So ANY keypair
both parties can derive is a valid address.

**The mechanism** (`node/src/drop.rs`). At key agreement both sides take a `drop_seed`
from the session's root key — the one value they share that, unlike the ratchet's `rk`,
does not move underneath them (`rk` advances per DH step and the two sides step at
different times, so it would derive different addresses). Each epoch (1 h) the seed
derives a fresh X25519 keypair; its public half is the box. Nothing is exchanged.

**The half that would have made it theater.** Rotating the address changes nothing on
its own: the relay reads `client_addr` on every request, and the per-process pseudonym
from the earlier fix was stable across epochs. A relay watching fetches would have
relinked every box to the identity mailbox polled beside it — beautiful rotating
addresses, reassembled for free. So handles are now per-purpose AND per-epoch
(`peer::Handle`), cookies are cached per handle (they are MAC-bound to `client_addr`),
and the opener poll keeps a handle of its own. Both halves are load-bearing; each was
neuter-verified against its own test.

**What it buys.** After the opener, a deposit no longer addresses the recipient's
published key. An observer holding someone's discovery key cannot read their inbound
social graph off deposit addresses. It is also the prerequisite for PIR.

### The residual, stated in full — and asserted by a test

**A relay that logs fetches can still chain a conversation's epochs together.** This is
structural, not an unfinished optimisation:

- Clocks are not synchronised, so a sender slightly ahead of a boundary deposits into an
  epoch the recipient does not consider current. To not lose that mail, the recipient
  polls `[e-1, e, e+1]`.
- Therefore box(E) is polled in three consecutive windows. A relay that logs sees the
  same address in adjacent epochs, links them, and chains the whole conversation
  transitively.
- Rotating the handle cannot fix it: on a re-poll the ADDRESS is the linker.
- Polling only the current epoch would close it — by silently stranding every message
  that crosses a boundary. That trades a metadata leak for disappearing mail, which is
  the worse defect and the exact bug-class this project rejects.

The honest fix is PIR: a fetch that does not reveal WHICH box is being read. It is its
own slice for a reason. Until then the gap is pinned by
`known_gap_the_relay_can_still_chain_epochs_through_the_overlap`, which asserts the leak
EXISTS and will go red the day PIR lands — the same pattern used for the opener leak.

**Also unchanged:** the opener still goes to the identity mailbox, because a stranger's
first knock needs one stable address to arrive at; and boxes polled back-to-back over
one connection correlate by timing and source address no matter what they are addressed
by — a transport concern (§15 path isolation), not one addressing can fix.

**Cost, named:** a poll now costs `3 × sessions + 1` fetch round trips. That is
bandwidth and latency, **not quota** — `handle_fetch` charges no capability quota (it
checks the cookie and the ownership proof; deposits are the metered path). An earlier
version of this section said fetches were quota'd and that persisting cookies was needed
to avoid exhausting it. That was wrong on both counts: persisting handles/cookies matters
because a fresh handle pays a `NeedCookie` round trip per box per process, which delays
delivery — the quota was never involved. Corrected against the code rather than left to
propagate. If the round-trip count ever binds, the fix is a batched multi-mailbox fetch —
but batching under ONE `client_addr` would relink the boxes and undo the slice.

### The silent-loss bug this slice shipped with, and how it was fixed (audit cycle 2)

**As first written, being offline for more than one epoch lost mail permanently.** The
recipient polled `[e-1, e, e+1]` around its OWN current clock. But a message is deposited
into the box of the epoch it was SENT in and never re-deposited — so anything older than
that window sat at an address the recipient would never ask for again. It rotted until
the TTL sweep with no error anywhere: mailbox intact, relay honest, message unreachable.

It was also a REGRESSION. The old fixed IK-mailbox held everything until
`MAILBOX_TTL_SECS` (7 days), so an offline recipient got its backlog on reconnect.
Rotation quietly cut the async-delivery window from days to about an hour — which defeats
the point of having mailboxes at all.

The tests did not catch it: the rollover test only exercised a ONE-epoch gap, and every
other test polled at the same clock it sent at. Found in audit, fixed with
`a_message_survives_the_recipient_being_offline_for_several_epochs` (verified: restoring
the hot-window-only sweep reddens it).

**The fix — two windows, because they answer different questions:**

| Window | When | Size | Why |
|---|---|---|---|
| **Hot** (`poll_epochs`) — `[e-1, e, e+1]` | every cycle | 3 boxes/session | Where mail arriving NOW lands. The neighbours absorb clock skew: a sender slightly ahead of a boundary deposits into an epoch we do not consider current yet |
| **Sweep** (`sweep_epochs`) — every epoch within `MAILBOX_TTL_SECS` | every `SWEEP_INTERVAL_SECS` (10 min), and on first run (`last_sweep == 0`) | `TTL_EPOCHS + 2` = 9 boxes/session | Everything the relay could still be holding. Old mail is by definition not latency-critical, so it does not need the hot cadence — but it must be reachable, or the promise of store-and-forward is false |

`last_sweep` is persisted: the CLI/GUI runs a fresh `Peer` per poll, so in memory it would
reset every cycle and turn the slow sweep into an every-cycle one.

**This is why the epoch is 24 h and not 1 h.** The epoch length sets the cost of being
CORRECT, not just the granularity of rotation: the sweep must cover every epoch inside the
7-day TTL, which is ~170 boxes per session at an hour and 9 at a day. What the coarser
epoch gives up is nearly nothing today — a relay that logs already chains epochs through
the poll overlap, and the observer rotation actually defeats (one holding your published
IK) is stopped by any rotation at all. `TTL_EPOCHS` is derived from `MAILBOX_TTL_SECS`
rather than hardcoded, so moving either constant moves the window with it.

**Clock skew tolerance is ±1 epoch (24 h).** Beyond that a peer derives boxes nobody
polls. Relying on the relay's clock instead would mean trusting an untrusted party with
addressing.

## Loop cover traffic (plan slice 3, 2026-07-17)

**What was wrong.** A client deposited only when its user typed. The relay reads a
deposit's timing, so silence answered "is this user writing to anyone right now?" — and
"quiet for six days, then three messages in an hour" is a pattern no amount of
encryption touches.

**The mechanism.** `Peer::send_loop` deposits a well-formed `Ratchet` envelope of random
bytes into a box derived from our OWN identity secret (`drop::loop_seed`, domain-separated
and keyed from a different secret than any session's `drop_seed`, so a loop can never
collide with a contact's box). It comes back to us, so no one else's mailbox is spent.
It decrypts for nobody, including us: trial-decryption fails and yields `None`, which
disturbs no session because `decrypt` is transactional.

**The distribution is the mechanism.** Delays are EXPONENTIAL, not the uniform ±25%
jitter already used for poll cadence. An exponential is memoryless — how long you have
waited says nothing about how much longer you will wait. Bounded jitter does not have
that property: watch a few gaps, learn the window, subtract the cover rate, read the
real traffic underneath. `cover_delays_have_a_heavy_tail_that_bounded_jitter_cannot_produce`
rejects a constant AND rejects the existing `Jitter::interval` (verified by neutering to
each), which is what makes it a test rather than a graph.

**Cover is a knob** (`WorkerCfg::cover_traffic`), because it is a permanent bandwidth
and battery tax. It also competes with real sends for the capability quota, but only via
its DEPOSIT — the fetches that read a loop back are free. At one loop a minute that is
~10 of the 100 requests per 600 s. A cost the user is entitled to decline.

### The residual, stated in full — and asserted by a test

**Against the relay itself, this currently buys much less than it appears to.** The
relay terminates our TCP and reads the source address on both legs:

- A real message's box: a deposit from the sender, a fetch from the RECIPIENT — two
  addresses.
- A loop's box: both legs from one address, ours.

The per-epoch handles do not help; the IP sits below them. This breaks BOTH things loops
are for:

1. **Volume cover** — the relay filters loops out of our total.
2. **Drop detection — and this one is actively dangerous.** A relay that can tell loops
   from real mail drops the real mail while faithfully returning the loops. The detector
   then reports all-clear while messages vanish. A detector that lies on demand is worse
   than no detector, so this must not be presented to a user as a working integrity
   signal until the residual is closed.

Both benefits were therefore CONDITIONAL on the two legs riding independent paths — and
**slice 3b (below) delivered exactly that, so this gap is CLOSED.** The legs are split
across two handles (`LoopSend`/`LoopRecv`) and per-handle isolation turns two handles into
two circuits, so a loop now shows the relay two source addresses, the same shape a real
message has. The pin was inverted into
`a_loops_two_legs_ride_different_circuits_like_a_real_messages_do` rather than deleted —
that is what pinning a gap is for.

**What remains conditional:** circuits only exist over an isolating carrier. Over direct
TCP there is one source address however many handles ask for one — you have one IP, and no
addressing scheme conjures a second. That residual belongs to the carrier the user picks.

**Also named, not solved:** the E2E layer does not pad, so real ciphertext lengths vary
while a loop's is fixed. The Noise layer's size buckets hide this from an on-path
observer but NOT from the relay, which sees the payload after decrypting the transport.
A relay comparing size *distributions* can still separate the populations.

**Garlic bundling (the third part of this slice) is not started.**

## Per-handle path isolation (plan slice 3b, 2026-07-17)

> **P0 fix (audit, 2026-07-17): SOCKS isolation now FAILS CLOSED.** With an isolation token
> the client used to offer the proxy both user/pass AND no-auth, so a proxy that could not
> isolate simply picked no-auth and the connection proceeded on a SHARED circuit —
> isolation failing invisibly, compartments looking separated while riding one circuit.
> Now, with a token, the client offers ONLY user/pass and refuses a no-auth selection: a
> proxy that will not isolate is hung up on rather than silently used. Pinned by
> `isolation_fails_closed_when_the_proxy_will_not_isolate`.

**Why it exists.** Slices 2 and 3 rotate identifiers — mailbox addresses, `client_addr`
handles, traffic timing. All of them sit ABOVE the IP, and the relay terminates the TCP,
so it reads the source address on every leg and relinks what they separated. Rotation is
undone underneath. This was not a new feature but the missing half of two slices already
shipped, which is why it was promoted ahead of node-roles/federation.

**What changed.** Every handle asks the carrier for its own circuit. The machinery was
already there — `Socks5Adapter::isolated`, `isolation_token()`, and Tor's
`IsolateSOCKSAuth` doing the actual enforcing — and only the granularity was wrong: one
token per `Relay`, i.e. per compartment. Now the compartment token and a per-request scope
are **combined**, because both separations must hold at once: two accounts must never
share a circuit (the compartment axis), and within one account two unlinkable handles must
not either. Dropping one to make room for the other would trade one guarantee for the
other.

**The scope is a hash of the handle, not the handle.** The relay reads the handle in the
clear as `client_addr`; the proxy sees the scope. Passing it verbatim would let a proxy
operator and a relay operator join their logs on an exact string match instead of on
timing — the design's whole bet is that those two parties cannot combine. Guarded by
`the_scope_handed_to_the_proxy_is_not_the_handle_the_relay_reads`.

**Threading.** Added as default trait methods (`connect_isolated`, `send_isolated`,
`fetch_isolated`) so the six `Transport` and four `TransportAdapter` implementations keep
working. That is a correctness choice, not a convenience one: a transport with no circuits
to separate should say so by inheriting the default rather than accepting a parameter it
silently discards — otherwise a test could assert an isolation production does not have.

**What it closed:** slice 3's loop-cover residual, outright (see above).

**What it does NOT close:**

- **Only over an isolating carrier.** Over direct TCP there is one source address however
  many handles ask for one. You have one IP.
- **Nothing about fetch ADDRESSES.** Slice 2's epoch-chaining gap is untouched: a relay
  that logs still sees the same box polled in adjacent epochs. That is PIR's job.
- **Cost:** a circuit build per handle (seconds, over Tor). The rate is a real design
  question rather than a detail — it was not tuned here.

**A spec contradiction this surfaced (fixed): `MAX_PACKET_SIZE` was 1400 and could not
carry a post-quantum opener.** An ML-KEM-768 key agreement is ~1.1 KB by itself, so first
contact with a message longer than ~120 B was dropped as oversize — silently, via
`DropNoReply`, before this slice existed. A spec mandating PQ key agreement AND a ceiling
too small to carry one is inconsistent; the ceiling was the arbitrary half (it is a
bounded-parse DoS gate, not a link MTU — the live path is TCP inside Noise, which frames
and reassembles). Now 2560, sized from the real protocol. Guarded by
`a_post_quantum_opener_carries_a_full_length_first_message` (put 1400 back → first
contact vanishes).

**The ceiling stands regardless.** A single relay that terminates your TCP and watches
your fetches can correlate deposits by IP + timing — sealed sender's known weakness.
Only mix-routing / multiple non-colluding relays break it, and neither exists here.

## Status by module

| Module (§) | Class | What is real |
|---|---|---|
| `params` (7.0) | ✅ Real | protocol parameters |
| `cookie` (7.1) | ✅ Real | stateless cookie, HMAC-SHA256, 2-key rotation, constant-time comparison |
| `capability` (7.2) | ✅ Real | symmetric HMAC capability + proof, scope/expiry check; `CapabilityQuotaTracker` (enforcement of max_requests/max_bytes per window + anti-replay across the epoch boundary) |
| `rln` — core+tracker (7.4) | ✅ Real | nullifier + Shamir slashing over the Curve25519 scalar field; `RlnQuotaTracker` (double-spend detection → deanonymization of a violator; epoch-freshness check + grace window) |
| `pipeline` (7.5/7.6) | ✅ Real | staged pipeline (Stages 0–5), bounded replay filter, live/DTN branching |
| `dtn` (7.7) | ✅ Real | DTN class: HMAC capability without an epoch (+ `max_bytes` enforcement), per-peer + device-wide carry budget (Sybil defense), PoW throttle, rolling-window replay; integration into Ingress (`process_dtn`) |
| `tring` (7.3) | ⚠️ Reference / NOT audited | CDS threshold ring signature over Ristretto255; **only behind `--features unaudited-crypto`**, off by default |
| `rln` — zk wrapper (7.4) | 🔒 Stubbed | `ZkProofStub` — the proof of membership in the tree of admitted identities is not implemented |
| `node::node` (skeleton) | ✅ Real (skeleton) | RelayNode + Client + in-memory transport, real cookie round-trip; **epoch wiring** (monotonic advance by the server's clock, lazy cookie-key rotation, coherent with the pipeline epoch) + **client cookie refresh**; **fetch-auth** (authenticated mailbox fetch: cookie + static-static DH proof of ownership, a failure does not drain); **fixed-size fetch** (§2.2): a fetch returns a constant-size page (`FETCH_CAP` seals max, greedily packed, remainder deferred to the next poll), so the response length no longer leaks the queue depth — the tradeoff is bandwidth (every poll pays the full page) for metadata (discriminating wire-byte-count test: empty vs full fetch = identical bytes); **persistent node key** (relay-id is stable across restarts); mailbox; **§7 admission is ENFORCED** on the deposit path (`handle` runs the real `AdmissionPipeline`: cookie → replay → capability HMAC + quota); a Private relay gates on a random invite capability, a Public relay on a **PoW-earned** one (slice 4a), and the known dev-cap is `KARST_RELAY_MODE=dev` only; **resource hygiene** on top (bounds FD/memory for an untrusted relay): a `ConnLimiter` caps concurrent connection-handler threads (RAII permit, released on drop/panic), and a lazy mailbox TTL sweep piggybacked on the epoch advance drops undelivered mail older than `MAILBOX_TTL_SECS` (7 days); the message-path core |
| `node::session` (§15) | ✅ Real (skeleton) | **Noise_NK via `snow`** (Apache-2.0/MIT, pure-Rust resolver): encrypts the whole wire, authenticates the relay to the client, per-session FS; chunked Noise frames with bounded reads. **Length-hiding padding** (§2.2): the payload is padded to fixed size buckets before encryption, so an on-path observer sees only a size class, not the exact message length (both directions; discriminating wire-byte-count test). Confidentiality + anti-MITM + message-size hardening — still NOT transport obfuscation (the handshake is identifiable by traffic classification and IP/port-blockable) |
| `node::transport` (§15 seam) | ✅ Real (skeleton) | pluggable transport: `Channel`/`TransportAdapter` + `DirectTcpAdapter` + `Socks5Adapter` (CONNECT, no-auth, a route through an external PT — Tor/obfs4/…). No silent fallback to direct. External-PT obfuscation is in the external transport, not here. `Path` (carrier + endpoint) is the §15 Path Manager's unit; **path SELECTION lives in `node::socket::SocketTransport`**, which retries connect AND the Noise handshake across an ordered path list. Bounded by `CONNECT_TIMEOUT` (a blackholed IP would otherwise hang tens of seconds) and `READ_TIMEOUT` (a silent path errors instead of wedging the client). The client builds the list from the chosen carrier + `KARST_RELAY_ALTS` + `KARST_PATHS` — see the endpoint-availability note below |
| `node::wss` (§15 carrier) | ✅ Real · wired end-to-end | **WebSocket-over-TLS carrier** — the first carrier KARST implements ITSELF (not just a seam): the Noise session rides inside an ordinary `wss://` connection (sync `tungstenite` + `rustls` on the `ring` backend). `WssAdapter` (client) + `accept_wss` (relay) + a byte-stream shim over WS binary frames. **Wired into the binary:** `karst-relay` reads `KARST_RELAY_TLS_CERT` + `KARST_RELAY_TLS_KEY` (PEM) and terminates `wss`; the client picks it via `KARST_WSS=<host>` (SNI); `KARST_WSS_ROOT_CA=<pem>` adds an extra trust root (self-hosted private CA / local testing) on top of the webpki roots. `scripts/karst-wss-demo.sh` runs a full local round-trip over wss. The client carrier composes over an inner transport, so `KARST_WSS` + `KARST_SOCKS5` together route the wss **through** SOCKS (rides standards-compliant wss *and* an external PT — defense in depth; test uses a spy inner adapter). **TLS here is transport encapsulation, not security** — Noise already authenticates the relay end-to-end; the client verifies real webpki roots, presents a real SNI, and advertises browser-like ALPN (`h2` + `http/1.1`) so the ClientHello looks ordinary (a self-signed cert or a missing ALPN extension would each be a fingerprint). Tests: first bytes on the wire are a TLS ClientHello (`0x16 0x03`) advertising ALPN not the Noise prologue (direct-TCP negative control); a >64 KiB multichunk round-trip; and a full `RelayServer::with_tls` ↔ `WssAdapter` fetch through the real serve loop. **Still open:** SNI is cleartext (no ECH), the relay IP is a fixed blockable endpoint, active probing is undefeated; and HTTP/3 (needs QUIC/async), WebRTC, Wi-Fi, Bluetooth do not exist |
| `node::wire` + `node::socket` (§15) | ✅ Real (skeleton) | TCP + postcard **inside a Noise session**, via the transport adapter; a mandatory tunnel (no plaintext fallback); the **external trust boundary** on the handshake frames; the `karst-relay` binary |
| `node::pqxdh` (2.1) | ⚠️ Real (reference, NOT audited) | **PQXDH** — a hybrid of X3DH + ML-KEM-768 (`ml-kem` FIPS 203): sender authentication (IK_A in the DH) + a post-quantum root_key; the KEM-ct + both DHs + both long-term keys are bound into the transcript. The primitives are vendored, the X3DH composition is reference (needs an audit). A key-agreement form (`initiate_key_agreement`/`accept_key_agreement`) — it seeds the `root_key` for `ratchet`; woven into the in-process path via `peer` (bundles in-memory) |
| `node::ratchet` (2.1) | ⚠️ Real (reference, NOT audited) | **Double Ratchet** (classical X25519, the Signal spec) over the PQXDH `root_key`: per-message FS (non-retention mk, one-way `KDF_CK`) + PCS (a DH step weaves in a fresh ephemeral). Transactional `decrypt` (AEAD before committing the chain), header in the AAD. **Out-of-order tolerant** (skipped keys, the Signal spec) including the chain boundary: `MAX_SKIP` (anti-KDF-DoS) + `MAX_STORE` FIFO. Transactionality gives a property ABOVE Signal — a forged high-`n` does not fill the store. The FS trade-off (skipped mk at rest — named). No HE/PQ ratchet |
| `node::peer` (2.1) | ⚠️ Real (reference, NOT audited) | The session **E2E of the message path**: PQXDH+ratchet over admission→mailbox→fetch-auth. `Payload::Session(Initial\|Ratchet)`, the relay is opaque. Unconditional chain advance (nonce uniqueness > liveness), trial-decrypt routing. **§12 discovery** (`publish`/`connect` via the relay). In-process only (socket/CLI — needs session persistence); 1:1 |
| §12 discovery (`node` publish/fetch bundle) | ⚠️ Real (reference) | The relay stores + serves the prekey bundle: writing is gated by an **ownership proof** of IK ownership (the write-side mirror of fetch-auth) + cookie + a bounded `MAX_BUNDLES`; reading is public. The relay is NOT an identity anchor: an IK swap = MITM (**external wall**: OOB/TOFU verification of the IK); a prekey/KEM swap → fail-closed |
| `node::safety` (2.1) | ✅ Real | **Safety number** for OOB verification of IK authenticity: a pure symmetric `SHA-512` function of a pair of IKs → 60 digits (12×5, zero-pad; Signal format). Addresses the §12 "external wall" (OOB verification of the IK). Complete: it verifies IK authenticity, and that is sufficient (IK ⟹ session, see `pqxdh` DH1). Frozen KAT + symmetry/sensitivity. Shown in the GUI; **display-only** (the verified flag is not stored) |
| `node::seal` (2.1) | ⏳ Deferred (skeleton for socket/CLI) | classical-only sealed-box; NOT §2.1 (no sender-auth/FS/PQ). Carries the socket/CLI path (`Client`/`Recipient`) until session persistence is added there; the in-process path is on `peer` |
| `client::content` | ✅ Real | **Content envelope** over the byte-level E2E (`node`/`peer` stay content-agnostic): `Content::{Text,FileManifest,FileChunk}`. **File transfer** across the 1400 limit — chunking (≤1024 B/chunk) + reassembly with a SHA-256 check. Anti-DoS: an absurd manifest/oversize/concurrency limit — before allocation. First slice ≤256 KiB (one mailbox). Tests: byte-for-byte round-trip, corruption detection (discriminating), missing-never-completes |
| `client::seed` | ⚠️ Reference / NOT audited | **Mnemonic phrase (BIP39) — the single root of identity.** 12 words → `to_seed("")` (PBKDF2-HMAC-SHA512, 2048) → `HKDF-SHA256` → 160 B = seal(32)‖account(128). One phrase → the same IK on any device (recovery). Wordlist/checksum — the `bip39` crate (MIT, pure-Rust). **The `derive` circuit is FROZEN** (KAT `frozen_derivation_vector`) — a compatibility contract: it cannot change, or it would orphan written-down phrases. **NOT wallet-compatible** (KARST's own HKDF over the BIP39 seed). **Losing the phrase = losing the identity FOREVER** (there is no backdoor). Tests: KAT, determinism, rejection of a bad checksum (discriminating), word confirmation |
| `client::secretbox` | ✅ Real | **At-rest**: `Argon2id(passphrase)` → a master key, then `HKDF(master, label)` per file; `XChaCha20-Poly1305` with a fresh random 24-B nonce per write, the label and a `STATE_VERSION` in the AAD. Pinned KDF profile **m=131072 KiB, t=3, p=1** (raised from OWASP's 19 MiB floor — CRYPTO-34); a `cfg(debug_assertions)`-only `KARST_INSECURE_FAST_KDF` hatch keeps the test suite fast and cannot exist in a release build. Protects the COLD disk, NOT the hot process. Tests: wrong-pw→reject, no plaintext on disk, fresh-nonce-per-write, cross-account/cross-file splice rejected, newer state version refused |
| `client::store` | ✅ Real (skeleton) | storage under **at-rest encryption**. **A single root**: `seed.key` (the phrase entropy); `load_identity`/`load_account` **derive** the keys (`seed::derive`) — disk and phrase do not diverge. `Store::unlock(dir, pass)` (single-account, CLI) + `Store::at(dir, key)` (over a ready key). **`Vault`** — multi-account: ONE device passphrase (Argon2id once) → a `MasterKey` for ALL accounts (`accounts/<ik>/`), switching is free (the same key); the `accounts.dat` registry is encrypted. At-rest keys are derived PER (account, file) from the device key (`HKDF(master, label)`), so one account's sealed file cannot be opened in another's slot, nor under another file's name (CRYPTO-05); the legacy single-account migration was removed with format v2 — a bare pre-vault directory stays a standalone `Store`. The passphrase ≠ the phrase. Relay keys are not encrypted |
| `client` (lib+bin `karst`) | ✅ Real (skeleton) | orchestration over `SocketTransport`; the CLI **init** (prints the recovery phrase) / **restore** (from the phrase) / **show-phrase** / id/account/dev-cap/import-cap/**publish**/send/**send-file**/recv **entirely on §2.1** (identity from the root phrase; persistent ratchet sessions under flock, atomic write; §12 discovery; **at-rest** via `KARST_PASSPHRASE`; text and files via the `content` envelope). A dev capability with a public secret |

**"Real"** = implemented with a real crypto library and covered by adversarial
tests (not just the happy path). **"Reference / not audited"** =
cryptographically complete, but home-grown security crypto without an independent
audit — deliberately behind a feature flag. **"Stubbed"** = a stub, honestly
marked, that does not perform the check.

## The three external walls

Further progress toward a **working** (not reference) admission path runs into
dependencies that cannot be closed within this crate:

1. **RLN zk membership circuit** (circom/halo2). Without it, `RlnQuotaTracker` is
   a punishment layer *on top of presumably* zk-verified shares, not a full gate:
   an attacker can submit arbitrary `(nullifier, a1)`. So the RLN branch in the
   pipeline returns `RlnNotImplemented`, not Admit. Pinned by the test
   `rln_layer_works_but_pipeline_branch_not_implemented`.
2. **An audit of the threshold ring signature.** `tring` is a correct CDS
   construction, but home-grown; "more reliable" for a security primitive
   ultimately means an independent audit, which we don't have. Until then —
   feature-gated, "not for production".
3. **Poseidon → SHA-512** (in `rln`). The reference substitutes SHA-512 for the
   SNARK-friendly Poseidon. The verifiable property (recovering the secret from
   two shares) is field-based and does not depend on the choice of hash; Poseidon
   is needed only for cheapness *inside* a zk circuit, which is not here (see
   wall 1).

## What actually passes through the pipeline

**Live path** (`AdmissionPipeline::process`):
`cookie → format → replay (epoch) → crypto → Admit`. Stage 4 by credential type:
- `Capability` (HMAC) → Admit; ✅ works.
- `Token` (ring signature): `MockRingVerifier` (not crypto, for pipeline tests)
  or `RealRingVerifier` behind the feature (wall 2).
- `RlnQuota` → `RlnNotImplemented` (wall 1).

**DTN path** (`AdmissionPipeline::process_dtn`, §7.7):
`cookie → format → replay (rolling-window, read-only CHECK) → DTN-capability HMAC
→ insert after verification → Admit`. Fully works; the capsule identifier
`H(ciphertext)` binds the MAC and the replay key. Plus a separate carrier stage
(`CarryBudgetTracker`) before returning to the network. e2e:
`dtn_full_lifecycle_carrier_then_ingress`.

## The working skeleton (`impl/node`)

The first end-to-end MESSAGE path: a `Client` seals text → admission (§7, a real
cookie round-trip) → on Admit, `RelayNode` puts the sealed payload into a mailbox
→ a `Recipient` fetches and decrypts it. In-process (the `InMemoryTransport`
transport), but two real endpoints and a real handshake.

The load-bearing part is the **separation of layers** (tests/message_path.rs):
admission gates by credential and is blind to content, E2E is orthogonal to
admission. Proven by two tests: `relay_tampering_admitted_but_e2e_rejects` (the
relay Admits, but AEAD catches the payload tampering — the node has no key) and
`bad_capability_rejected_regardless_of_content` (a bad credential → Reject even
with a perfectly valid payload).

### The protected §15 session (`node::session`, Noise_NK via `snow`)

The whole wire goes inside **Noise_NK** (the node's responder-static is known to
the client out of band, like the address). It gives: confidentiality of all
traffic (not only the §2.1 payload, but also the admission metadata — cookie,
capability, the recipient's pubkey), **authentication of the relay to the client**
(anti-MITM — the client encrypts to a known static), **per-session FS**. The
crypto is `snow` (the de-facto Rust Noise, Apache-2.0/MIT, a pure-Rust resolver
for our stack and Android), NOT home-grown. `relay-id` = Noise-pub ‖ fetch-auth-pub,
printed by the binary.

**Admission is preserved ON TOP of the tunnel** (§15 requires it explicitly):
cookie/capability/fetch-auth are presented even after encryption — otherwise an
attacker bypasses quotas through a thousand VPNs. **The tunnel is mandatory — no
silent fallback to plaintext** (the same "no hidden fallback" as in §15): a
handshake failure = a hard error, not a rollback to an open protocol.

The load-bearing test (tests/socket_path.rs): `wire_bytes_are_ciphertext_recipient_metadata_hidden`
— a writing proxy on the wire, the recipient's pubkey (open postcard WITHOUT
Noise) is ABSENT on the wire (it would fail if encryption were a no-op — unlike
the check of the text itself, which is E2E-encrypted anyway);
`mitm_wrong_noise_key_fails_handshake` — a foreign Noise key drops the handshake,
no data flows. A live CLI smoke confirmed it (send/recv inside Noise; a wrong
relay-id → a hard error).

**The session itself is NOT transport obfuscation.** A Noise handshake is recognizable by traffic classification
(msg1 is a high-entropy ephemeral with no TLS structure); IP:port blocking works
over encryption. Transport encapsulation comes from the SEAM below — through an
EXTERNAL PT. Residual (named, not fixed): the handshake is unauthenticated node
work per connection (ephemeral+DH before the cookie) → CPU-DoS on top of the
already-named unbounded number of threads; the node's Noise-static is ephemeral
across restart (persistence is a separate slice).

### §15 transport encapsulation — a SEAM, not an implementation of its own (`node::transport`)

The spec is explicit: "pluggable transports — an interface, not an implementation
of its own". Any transport-level obfuscation comes from an EXTERNAL, vetted transport
(Tor/obfs4/Shadowsocks/meek); KARST provides only the wiring. Here: `Channel`
(`Read+Write+Send`) + `TransportAdapter` + `DirectTcpAdapter` + `Socks5Adapter`
(CONNECT, no-auth, RFC 1928). The Noise `Session` did not change — it is already
generic over `Read+Write`, and the adapter returns a `Box<dyn Channel>`. CLI:
`--socks5 HOST:PORT` (point it at a local SOCKS port of a PT client — Tor `9050`
etc.). **GUI:** a "SOCKS5 (Tor/obfs4)" field in the unlock window — the worker
threads the proxy into ALL three calls (`send`/`recv`/`publish`). Previously the
desktop GUI hard-coded the proxy to `None` → the proxy transport was UNREACHABLE
from the main product (the same pattern "a mechanism exists, the product does not
reach it" that the safety number closed).

**An honest heading:** KARST can now route through an external proxy transport — but
IT provides any transport-level obfuscation, not KARST. "We can point it at Tor", not
"KARST invented its own obfuscated transport".

**The scope of the guarantee (named):** a route through an external PT lets the client
reach the relay across a user-chosen network transport when a direct path is
unavailable, NOT anonymity from the relay — the relay still sees your
`identity_public()` and mailbox activity. Tor hides the network location, not the
application-level identity.

**No silent fallback (§15):** an unreachable SOCKS proxy → a hard error, NEVER a
direct connection (otherwise it deanonymizes whoever chose Tor). Load-bearing
(tests/socks5.rs): `routes_through_socks5_proxy` — the stub VALIDATES the SOCKS5
handshake and forwards, and a full Noise round-trip passes through it (it checks
the seam + correct SOCKS5, NOT "obfuscated"); `socks5_dead_proxy_hard_fails_no_direct`
— a dead proxy → `Reject` (a direct fallback would have returned Accepted). A live
CLI smoke confirmed: `--socks5` at a dead port → error, the recipient's mailbox is
empty (there was no direct connection).

**Endpoint availability — path failover (NOT the whole story).** The client can be given more than one route to the relay: the primary
(chosen carrier + `addr`) plus `KARST_RELAY_ALTS` (comma-separated `host:port`)
alternate endpoints reached with the SAME carrier. `SocketTransport::round_trip_sized`
tries the paths in order and uses the first whose **connect AND Noise handshake** both
succeed, bounded by `CONNECT_TIMEOUT` (≈5 s) and `READ_TIMEOUT` (≈15 s) — so a
blackholed IP *and* an on-path classifier that accepts the SYN then kills the handshake are both
routed around. **The retry boundary is deliberate:** nothing is retried once the
request has been written, because the relay may already have applied it (a deposit is
not idempotent) and a retry on another path could duplicate it — an honest error beats
a silent double-send. **What the tests
actually guard** (all e2e through the real relay socket): a dead primary is skipped for
a live alternate (`failover_skips_dead_primary_and_reaches_live_relay`); a path that
ACCEPTS TCP then never speaks Noise is abandoned for the live relay
(`failover_skips_a_path_that_accepts_tcp_then_stalls_the_handshake` — neutered the
retry back to connect-only and confirmed it reds); all-dead ERRORS rather than
inventing a path (`failover_all_paths_dead_fails_never_silent_fallback`), as does an
empty list (`transport_with_no_paths_errors`);
and that the path assembly parses `KARST_RELAY_ALTS` in order and skips garbage
(`parse_alt_paths_keeps_valid_in_order_and_skips_garbage`). **Automatic transport SWITCHING + the no-downgrade
allowlist (`KARST_PATHS=kind@ip:port,…`, kind = direct|socks5|wss|wss+socks5).** Extra
routes may use a DIFFERENT carrier, so if an adversary blocks direct and wss the client can still be
routed around via Tor. Every spec is filtered through `allowed_carriers(intent)`, an
**intent-derived allowlist — deliberately not a scalar strength ordering**, because wss
(anti-traffic-analysis) and SOCKS5 (anonymity via an external PT) defend against different
adversaries and do not substitute for each other: a Tor user's list drops `direct` AND
bare `wss` (both exit from this host = deanonymization); a wss user's drops `direct`
and bare `socks5`; asking for both leaves only `wss+socks5`; asking for nothing allows
all. A carrier whose prerequisite config is missing (wss with no SNI host, socks5 with
no proxy) is SKIPPED, never demoted. **This is now test-guarded, not by inspection:**
`filter_allowed_drops_a_live_direct_path_for_a_wss_user` gives the config a WORKING
direct route + a dead wss route under wss intent and asserts only the wss route
survives — the connection may fail, but never silently uses the live direct one
(neuter `filter_allowed` to the identity and it reds; verified). **Honest scope — this is ONE layer:** it defeats port-blocking,
connect-time IP-blackholing, and a handshake-killing on-path classifier across the routes you already
know, on the carriers you allowed. It does **not** address (a) tampering that survives
the handshake, or an adversary who lets everything through and simply drops the relay's
answers mid-request (nothing is retried past the write — see the boundary above);
(b) the cleartext-SNI traffic-analysis vector (ECH — see the wall below); (c) DISCOVERING new
relay endpoints once the known ones are blocked (the §12 rendezvous/bootstrap
problem); (d) route configuration is now IN THE APP — the login/create screen's
"Network (relay)" section has an **extra routes (failover)** field taking the unified
syntax (`ip:port` = another endpoint on the chosen carrier, `kind@ip:port` = an
explicit carrier). The envs (`KARST_RELAY_ALTS`/`KARST_PATHS`) only PREFILL that field
now; the worker builds `Relay::configured` from what the user actually sees, so the
library no longer reads process env per call. The CLI still takes its relay config from
flags/env (`relay_arg`). **The config is remembered** (`Vault::save_net`/`load_net`,
`net.dat`): typed once, a later launch unlocks with the passphrase ALONE and the worker
applies the saved relay + routes — escape routes you must retype under pressure are
routes you will not use. Deliberately encrypted at rest, NOT a plaintext config: a
lost or stolen cold disk must not reveal the relay this device speaks to or its escape routes.
The price is the ordering — the config is unreadable until the passphrase opens the
vault, so it is applied post-unlock rather than prefilled into the fields. Tests: the
config survives a restart and no plaintext relay/route bytes are in `net.dat` (write it
in the clear → reds); a worker e2e provisions with a config, restarts, unlocks with the
passphrase only, and still publishes to the relay (neuter the saved lookup → reds).

**Per-path health (cooldown).** Each `Path` carries an `Arc<PathHealth>`, so the
state survives the per-request transports built from the same list: a route that fails
to connect/handshake is deprioritized with an exponential backoff (10 s base, doubling,
capped at 300 s), and a success clears it at once. Selection order = paths out of
cooldown first (in priority order), cooling ones AFTER — never excluded, so a total
outage always recovers and a long-dead route is still re-probed. This kills the stall a
blackholed primary used to cost on EVERY request. Test-guarded:
`health_stops_retrying_a_dead_path_on_every_request` counts connect attempts on a dead
primary — 1 on the first request, still 1 on the next (neutered the health ordering and
watched it climb to 2; verified), plus unit tests for backoff/reset/cap and that a
`Path` clone observes the original's failure. It is scheduling state, not security: it
never changes WHICH carriers are allowed.

**WALL — discovery when the endpoints you know are blocked (§12), characterized
(2026-07-17).** This is the largest remaining lever, and the honest finding is that the
*obvious* implementation would help an adversary. The design space and what each option
actually costs:

1. **The relay advertises its own alternate endpoints.** Tempting: no new trust (the
   relay already sees your IP, so learning more of ITS addresses leaks nothing new to
   it), no user action, and it pre-seeds alternates before a block lands. **But an
   endpoint list is only safe if admission genuinely gates WHO may ask — and today it
   does not.** The dev-capability secret is public and forgeable by anyone
   (`dev_capability`, "кто угодно может его подделать"), and cookies are issued to any
   (client_addr, carrier_id) — they are anti-spoofing, not authorization. So an adversary
   would connect once and enumerate every IP to blackhole: the feature would hand the
   adversary its own blocklist. **Blocked behind the same wall as blob DoS attribution:
   real capability provisioning (§7.2) does not exist.** Not built, deliberately.
2. **Contact route sharing over the E2E session — BUILT** (`Content::RouteOffer`).
   Its decisive advantage over (1): an adversary cannot enumerate it — offers are E2E
   encrypted between contacts, so there is no list to ask for. **Both directions are the
   user's decision:** sharing is one explicit ••• menu click *addressed to one chosen
   contact* (never a broadcast, never automatic — handing someone your routes tells them
   where you connect from; the menu item says so on hover), and an arriving offer is
   stored PENDING until an explicit accept (connecting to an offered endpoint reveals
   your IP to whoever runs it, so arrival must never be consent). Only offers for the
   relay you already use are actionable: Noise authenticates that identity, so an offered
   route cannot impersonate it — the worst it can do is fail; an offer naming a different
   relay is ignored with a status (trusting a new relay with your metadata is a bigger
   decision than "another way to reach the one we share"). Accepted routes still pass the
   carrier allowlist, so an offer can widen your options but never lower your floor.
   Tests: an offer is never applied without an explicit accept and is consumed by it;
   sharing carries the chosen contact's ik; and an e2e through the real relay where Alice
   shares, Bob receives an offer, his saved config is UNCHANGED until he accepts (neuter
   it to auto-apply on arrival → reds; verified). **Honest limit: it pre-seeds, it does
   not rescue** — you must receive an offer BEFORE you are blocked, because receiving
   anything needs a working route.
3. **CDN / domain fronting.** A coercible intermediary — see the ECH wall; same
   Principle-3 conflict.
4. **DHT / well-known rendezvous.** The bootstrap list is itself the blockable thing;
   this relocates the problem rather than solving it.
5. **Out-of-band** (a friend, a QR code, paper, another app). Needs no code — type it in
   — and it is the ONLY option that rescues someone already fully dark. It is the honest
   baseline the others improve upon, not replace.

So: "KARST finds a way around a total block by itself" is NOT true and is not close.
What exists is (5) plus everything above that makes a *known* set of routes survive
being partially blocked.

**WALL — ECH (the cleartext SNI), characterized (2026-07-16).** Not "todo": it is
blocked twice over, and the second reason is a principle conflict, not a missing patch.
1. **Our TLS stack cannot terminate it.** `rustls` 0.23.42 implements ECH for the
   CLIENT only (`EchMode::Enable/Grease`); there is no server-side ECH — no server
   `EchConfig`, no HPKE key acceptance, no inner-ClientHello decryption. `karst-relay`
   IS a rustls server, so ECH to our own relay is impossible today regardless of effort
   on our side.
2. **The only near-term path conflicts with the independent-relays principle.** rustls's own docs are
   explicit that a client `EchConfig` comes from the ECHConfigList of *the server you
   connect to*, fetched from its DNS HTTPS record. So client-side ECH only helps when
   the endpoint already supports ECH — in practice a large CDN, i.e. putting the relay
   behind (or fronting through) a provider that can see the connection and
   drop you. That is a *trusted intermediary that can observe or disrupt the connection* —
   precisely what the independent-relays principle exists to avoid. ECH is therefore a design decision with a real
   tradeoff, not a free win, and it will not be taken quietly.
`EchMode::Grease` (sending a decoy ECH extension, as browsers do) is available and
would make the ClientHello marginally more browser-like — but it does NOT hide the SNI,
and on its own it is one extension inside a fingerprint that is rustls's, not Chrome's.
Real browser mimicry needs uTLS-style fingerprint cloning, which rustls does not offer.
Claiming GREASE as "SNI protection" would be a lie; it is not implemented for that
reason.

**Carrier is visible, not assumed:** the active §15 carrier is derived from one
source of truth — `client::active_carrier(proxy)` over `(KARST_WSS, proxy)`, the
exact inputs `transport()` branches on — and surfaced to the user: the GUI shows a
`via direct / SOCKS5 / wss / wss over SOCKS5` chip in the status bar, and the CLI
prints `carrier: …` before every networked command. So a user who chose a proxy or
the wss transport can *confirm* it is in effect rather than trusting it silently
(the pure `carrier_from` truth table is unit-tested).

**Client-side timeouts (both now bounded):** every path's TCP **connect** is bounded
by `CONNECT_TIMEOUT` (~5 s) and every **read** on the established socket by
`READ_TIMEOUT` (~15 s, set inside each adapter's `connect`, so it covers the SOCKS
handshake, the TLS/Noise handshake, and the response — all relay responses are small
and fast, so it never cuts legitimate traffic). A path that accepts TCP then goes
silent (a silent-drop on-path classifier, hung proxy) is now an **error**, not a wedged worker thread
(`read_timeout_turns_a_silent_peer_into_an_error_not_a_hang`). This is what makes handshake-level failover
work: the retry loop lives in `SocketTransport` around connect+`Session::connect`, so a
connected-but-silent path times out and the request moves to the next path. Both SOCKS ATYP branches are
covered (IPv4 `routes_through_socks5_proxy`, IPv6 `routes_through_socks5_proxy_ipv6`).

**GUI PT wiring — tests (gui/tests/worker_e2e.rs):**
`worker_routes_all_calls_through_configured_socks5_proxy` — a worker with
`socks5=<stub>`; the stub COUNTS the CONNECTs, and the test pins the counter's
growth after EACH of publish/send/recv separately (not only publish — send carries
the message content, testing it is mandatory). Discriminating per call: verified —
reverting ANY (`send`/`recv`/`publish`) to `None` → its CONNECT disappears → the
counter does not grow at that step → red (a silent proxy reset = deanon with no
error). `dead_socks5_hard_fails_no_direct_leak` — a dead proxy → publish fails
hard, and Alice (direct) did not reach Bob → his bundle did NOT go to the relay by
a bypass (no-fallback confirmed at the GUI layer).

**Length obfuscation — DEFERRED (defense-in-depth, honest about the limit):** on
the wire `write_msg` writes an open `u32` = the plaintext length (+ the lengths of
the ct chunks) → the message size is visible to a passive observer of a direct
connection. Padding into "buckets" would hide it, BUT: the relay terminates Noise
and sees the true lengths anyway (it can't be hidden from it), and when a PT is
used the external transport already obfuscates the channel. The value is only for
a direct connection / defense-in-depth; so not now.

**Transport roadmap:** length padding + fixed-size fetch (**built**, see above);
a **WebSocket-over-TLS carrier** (`node::wss`, **built and wired end-to-end** —
carries the encrypted protocol over standards-compliant wss; `KARST_RELAY_TLS_CERT`/`_KEY` on the relay, `KARST_WSS`
on the client); still named, not built: ECH/domain-fronting; a uTLS fingerprint; HTTP/3 (needs QUIC/async — the
current stack is sync); WebRTC; rich `Capabilities`/`probe`/`migrate`/`health`; a
Path Manager + multi-path; the Normal/Private/Anonymous profiles.

### Socket transport (`node::wire` + `node::socket`, the `karst-relay` binary)

The same message path goes **over a real TCP** between processes (inside the Noise
session above). The same `Transport` contract as `InMemoryTransport` —
`Client`/`Recipient` work over the socket unchanged. The codec is postcard.

**The external trust boundary is now the handshake frames (`session`).** Untrusted
bytes arrive BEFORE decryption: the bounded read moved onto the Noise handshake (a
`MAX_HANDSHAKE_MSG` cap, reject before allocation) and onto the Noise frame /
full-length fields inside the session — the same discipline (a clean error
instead of a panic/hang), verified by the same oversized/truncated/garbage tests,
now hitting the handshake reader. The internal postcard request ceiling is tied to
`MAX_PACKET_SIZE`.

**The server sets ITS OWN `now`** — time does not ride over the wire. Trusting the
client's time = letting it control cookie expiry and the quota window; the server
re-checks with its own clock.

Load-bearing coverage (tests/socket_path.rs) — **a malformed frame does not bring
down the server** (an analog of the layer-separation test for the network
boundary; an encode/decode round-trip is insufficient — it passes while the
decoder panics on 4 bytes): `oversized_length_rejected_without_alloc`,
`truncated_frame_errors_cleanly`, `garbage_body_rejected` (+ a liveness probe
after each) and `loopback_happy_path` (a real socket e2e). **Skeleton:** blocking
std-TCP, thread-per-connection, bare (no §15 transport obfuscation), `RelayNode` under a
`Mutex` — §15 (QUIC + transport obfuscation) will replace the loop with async; only the
`Transport` contract is durable.

**An unadmitted connection is on a short leash (R2-13).** Admission is applied per
request, INSIDE the Noise session — it cannot be applied earlier, because the
credential travels encrypted, so a peer with no intention of authenticating still
gets a connection slot and a handshake. Nothing fixes that ordering. What is fixed
is the cost of holding the slot: after `MAX_UNADMITTED_REQUESTS` (8) requests
without a single one getting past admission, the relay drops the connection instead
of letting it sit until `CONN_TOTAL_DEADLINE` (2 min). "Got past admission" is an
allowlist on purpose — only the classes that actually run the cookie/capability/quota
gate count, and only when the answer was not a refusal. The obvious denylist
("anything that is not `NeedCookie`/`Rejected`") would let a stranger buy the full
deadline with one `BlobStat`, since the public reads answer without looking at a
credential. Pinned by `a_connection_that_never_gets_admitted_is_dropped_at_the_leash`
(client e2e), which carries its own control: a legitimate upload sends MORE requests
than the leash allows and is untouched, because its second request is admitted.

**A gossiped address is only a place to dial (#232, CRYPTO-23 node side).** `gossip_round` used to
store the descriptor a PEER handed it, once `verify` confirmed a relay with those keys answered
there. Everything that check tests is also true of a transparent proxy in front of an honest
relay: the TCP lands on the proxy, Noise terminates at the real relay behind it, and the relay
serves its own relay-id correctly — so a peer could advertise `proxy → honest relay-id` and we
would adopt the proxy as the route, handing whoever runs it a permanent view of client IPs,
timing and volume plus a selective-drop switch, with the encryption intact. `verified_self_
descriptor` now returns the relay's OWN entry for itself and that is what gets stored; the
offered address is used only to dial. Comparing offered against self-declared was rejected on both
sides for the same reason: it needs canonicalisation across host-vs-IP, carrier, port and path,
and any rule strict enough to catch the proxy also rejects an honest relay spelled differently. A
relay that declares no address of its own is simply not stored — it is undiscoverable by its own
choice, and inventing an address for it is the behaviour being removed. Pinned by
`gossip_stores_the_relays_own_address_not_a_peers_proxy`, which runs a real transparent TCP proxy.

**The unsealed opener no longer exists (#232, A3-14 residual).** `SessionEnvelope::Initial`
carried the sender's long-term identity key in the clear, so a relay wanting the social graph
could read every edge off the openers; `InitialSealed` replaced it and `Peer::process` already
refused the legacy form. Keeping the variant meant the shape stayed EXPRESSIBLE, and a runtime
refusal is weaker than a form nobody can construct — so it is gone. Honest about what that
changes: postcard numbers variants positionally, so old bytes now decode as a different variant
and fail closed rather than being refused loudly. A free wire break at zero users, taken
deliberately.

**The relay cannot admit a token credential (#145).** The token-verifier field used to be
`MockRingVerifier`, the non-cryptographic structural stub the pipeline tests compose against. It
was never live — no wire request carries a `Credential::Token`; every relay path builds
`Credential::Capability` — but "unreachable" was a property of the current wire, not of the
relay, and the type was hardcoded, so the day some future request class carried a token, a check
of the signature's SHAPE would have been the whole of admission. The field now holds
`NoTokenVerifier`, which refuses every token, so introducing an audited verifier is a deliberate
type change visible in review rather than a config or feature-flag flip. `MockRingVerifier` also
lost its unit-struct constructor: it can only be built via `MockRingVerifier::for_tests_only()`,
so any use has to name what it is at the call site. `karst-relay` prints what admission rests on
at startup. Pinned behaviourally by
`the_relay_refuses_a_token_the_structural_stub_would_accept`, whose control arm shows the stub
itself accepting the same token. **Still open from #145:** separate demo/production binaries and
a production build that refuses to start without an audited verifier — meaningful once such a
verifier exists; today the honest statement is that the relay has none and admits nothing on its
behalf.

**Reads no longer queue behind reads (#142).** The relay handle is an `RwLock`, not a `Mutex`.
The read-only handlers — bundle lookup (which happens on every first contact), node list, policy,
blob stat, PoW policy — only read published state, and under one mutex they waited for each other
and for every send. Writers still exclude everything, which is correct: admission mutates the
replay filter, the quota windows and the epoch. Two things had to move for this: the node-list
rotation cursor became an `AtomicUsize` (a `Cell` is not `Sync`, so it would have made the whole
relay unshareable for reads), and the discovery LOOKUP stays a writer because a single-use record
is consumed on read. Pinned by `a_reader_does_not_block_another_reader`, which holds a read guard
for the whole assertion and requires a bundle lookup to still be answered — structural, not
timed; under a `Mutex` that shape is a deadlock.

**Mail work is off the global relay lock too (#142).** The queues and their durable log moved
into a `MailStore` behind its own lock, and the serve loop now takes the relay lock only to ADMIT
a send/fetch/ACK — cookie, replay, capability HMAC, quota, ownership proof, all pure relay state —
then releases it and does the mail work under the mail lock. On a durable relay that matters a
lot: the deposit's fsync used to run while holding the mutex every other client's admission
needed. `handle`/`handle_fetch`/`handle_ack` remain one-step wrappers for callers that are not the
serve loop. Two consequences handled explicitly rather than discovered later: the mailbox caps are
re-checked INSIDE the mail lock, because admission now runs under a lock that has been released by
the time the write happens and two concurrently-admitted deposits must not both claim the last
slot (pinned by `two_deposits_admitted_at_once_cannot_overfill_one_mailbox` — the one-frame
invariant from #162 is not allowed to become racy); and `RelayPolicy` reads a cached durability
flag rather than the mail lock, so answering `GetPolicy` never queues behind an fsync. The epoch's
TTL sweep uses `try_lock` for the same reason the blob sweep does. Pinned by
`a_mail_write_in_progress_does_not_block_admission`, which holds the mail lock (an arbitrarily
slow disk, no timing threshold) and requires an unrelated `GetPolicy` to still be answered — put
the deposit back under the relay lock and it never returns. **Named residual:** discovery, bundle
publication and the OPK batches still share the relay lock with admission, and mail operations
still serialize against each other. Sharding the mail plane by recipient is deliberately NOT done
yet: it needs either N logs or one shared log lock, which would re-serialize exactly what the
sharding was for.

**Blob I/O is off the global relay lock (#142).** The relay keeps one `Mutex<RelayNode>`, and
`handle_blob_put`/`handle_blob_get` used to do their FILE I/O — tens of KiB per chunk — while
holding it, so a single upload head-of-line-blocked every other client's send, fetch and ACK on
the whole relay (the connection cap bounds threads, not this serial bottleneck). The blob store
now lives behind its own lock: the serve loop takes the relay lock only to ADMIT a blob request
(cookie, nonce shape, capability, quota — all relay state), releases it, and does the I/O under
the blob lock. Lock order is always relay → blobs, and the epoch's blob TTL sweep uses
`try_lock` so housekeeping cannot reintroduce the stall. `BlobStat` likewise reads the store
outside the relay lock. Pinned by `a_blob_write_in_progress_does_not_block_ordinary_mail`, which
holds the blob store's lock (a stand-in for an arbitrarily slow disk, no timing threshold needed)
and requires an ordinary send to still be Accepted — put the write back under the relay lock and
the send never completes. **Named residual:** this fixes the largest offender, not the pattern.
Message delivery, fetch, ACK, admission, quota and discovery still share one mutex; sharding
mailboxes by recipient and giving admission/discovery their own ownership is the rest of #142.

**Durable mailboxes are opt-in (R2-5).** `RelayNode::enable_durable_mail(dir, now)` opens an
append-only `mail.log` (`node::mailstore`): a deposit is written and fsynced BEFORE `Accepted`
is returned, deletions (fetch drain, ACK, TTL sweep) are appended without an fsync, and the log
is replayed and compacted on start. The replay re-applies the LIVE bounds — `MAILBOX_TTL_SECS`,
per-mailbox `MAX_FETCH_SEALS`, table-wide `MAX_MAILBOXES` — so a file written before a bound was
tightened, or by anyone with disk access, cannot smuggle state past it. Fail-closed in both
directions: a relay told to be durable that cannot open its log refuses to start, and one that
cannot write a deposit answers `Rejected("MailNotDurable")` rather than an `Accepted` the
sender's outbox would retire against. Pinned by
`an_accepted_message_survives_a_relay_restart_when_the_operator_asked_for_durability` with the
existing volatile characterization test as its negative control,
`a_leased_message_returns_after_a_restart_but_an_acked_one_stays_gone` (the at-least-once
semantics, chosen not inherited), `a_replayed_log_is_re_bounded_not_trusted`, and
`a_durable_relay_that_cannot_write_rejects_instead_of_accepting`.

**Mailbox cap — no silent loss.** `fetch` drains the box before writing the frame;
if the queue outgrew `MAX_RESPONSE_FRAME`, the frame would not be written but the
box is already deleted → a silent loss of the entire queue of an offline
recipient. Closed by a cap on INSERTION (`MAX_FETCH_SEALS`): a full box =
`MailboxFull` to the sender (backpressure), the invariant "the box always fits in
one frame" holds by construction. Test `mailbox_cap_rejects_instead_of_silent_loss`.

**Epoch wiring (§7.1) — completed in the node.** Previously `RelayNode.epoch` was
nailed to 0: the epoch logic lived in `admission`, but the node did not turn it,
so epoch-scoped replay protection + cookie-key rotation over time did not work.
Now the node advances the epoch MONOTONICALLY by `cookie_epoch_id(now)` (a
wall-clock regression does not roll back or reset the replay filter), lazily
rotates the cookie keys only on an epoch change; the pipeline epoch and the
rotation are derived from one source → coherent. The client re-issues the cookie
on a challenge (a first contact AND a stale cookie), limited to one retry,
separate from a real capability Reject.

**What pins what (no overclaim):**
- the client cookie refresh — `client_refreshes_cookie_on_expiry` (node);
- the reset of the live replay filter on an epoch change —
  `roll_epoch_clears_replay_filter` (admission, discriminating: through the full
  pipeline the effect is masked by the quota tracker, so we check the primitive
  itself).

**Design fact: a cookie's freshness is held by the TTL, not the epoch.**
`COOKIE_TTL_SECS`=30 always fires before the epoch-key grace
(`GRACE_EPOCHS`×`EPOCH_DURATION`=600s), so cookie-key rotation gives NO observable
accept/reject effect beyond what the TTL already gives. The load-bearing effects
of epoch wiring are (a) rolling the live replay filter across epochs and (b) key
rotation hygiene, not cookie freshness.

**Honest limitations (not walls — skeleton limits):**
- a wall-clock regression WITHIN an epoch still shifts the cookie's 30-second
  freshness; the real fix is a monotonic clock, outside this slice;
- a hung/slow client (slowloris) is bounded by `CONN_READ_TIMEOUT` (30 s) — a hang
  turns into a clean error, but **the number of handler threads is unbounded**
  (thread-per-conn); backpressure on accepting connections is a §15 task;
- `Mutex` poisoning in `RelayNode`: there is no panic path inside the lock today,
  so it does not trigger; if one appears — fail closed, NOT resume on possibly
  corrupted security state;
- `server_alive` in the tests proves the listener's liveness and a clean shutdown,
  not the absence of a panic in the handler.

**`seal::SkeletonSeal` — classical-only, this is NOT §2.1.** A sealed-box
(ephemeral X25519 → HKDF-SHA256 → ChaCha20-Poly1305). It does NOT have:
- **sender authentication** — a sealed-box gives Bob confidentiality but does NOT
  say the message is from Alice; anyone can seal to Bob. Real §2.1 (X3DH/PQXDH)
  authenticates the sender by her long-term key. **Consequence:** admission (§7)
  authenticates Alice TO THE RELAY, not to Bob — these are different sides; the
  recipient's assurance comes only from the E2E layer, which is not here yet (this
  reinforces the layer-separation theme);
- forward secrecy, Double Ratchet, and post-quantum protection — and §2.1 is
  needed exactly against harvest-now-decrypt-later.

Its purpose is to prove the path composes, not to truly protect the content.

> **Size limit in the skeleton.** The payload goes over the live path under
> `MAX_PACKET_SIZE` (1400 B) → messages larger than ~1.2 KB will be rejected by
> Stage 0. For real sizes you need §21.1 chunking or the DTN path
> (`MAX_DTN_CAPSULE_SIZE` 1 MB). The same class as the MTU-cap caught earlier in
> DTN.

**`seal` is replaced by `pqxdh`** (below) — but while the node path uses seal, it
is deferred, not a wall.

## §2.1 PQXDH — authenticated post-quantum agreement (`node::pqxdh`)

A hybrid of X3DH + ML-KEM-768 (spec §2.1): `root_key = HKDF(DH1‖DH2‖DH3‖pq_shared)`.
The sender: `initiate_key_agreement(IK_A, bundle_B) → (root_key, KA)`; the
recipient: `Account::accept_key_agreement(KA) → (root_key, sender_ik)`. The module
ONLY agrees a key — the messages are encrypted by Double Ratchet
(`node::ratchet`), not this layer.
- **Sender authentication**: `DH1 = X25519(IK_A, prekey_B)` — only the holder of
  the private IK_A agrees the same root_key. Load-bearing:
  `cannot_impersonate_alice_without_her_identity_key` (a swapped IK → the
  recipient gets a DIFFERENT root_key than the forger).
- **Post-quantum**: ML-KEM-768 (ek 1184 B / ct 1088 B); `pq_shared` IN the IKM.
  `pq_shared_is_load_bearing_in_root_key` (white-box) +
  `corrupt_kem_ciphertext_breaks_agreement` (end-to-end: a corrupt ct → diverging
  root_key). Hybrid → you must break BOTH X25519 AND ML-KEM.
- **Transcript binding**: both IKs, the ephemeral, the prekey, and the **KEM-ct**
  in the KDF-info — otherwise a KEM-substitution attack (an adversary swaps their
  own encapsulation).

**Crypto discipline:** the primitives are vendored (`ml-kem`/`x25519-dalek`/`hkdf`);
the X3DH composition is **reference code** (an exact public spec, like admission),
**NOT independently audited** — the external wall here is an audit, not the
implementation. NOT feature-gated (E2E is the core of the product, unlike tring).

**This slice's boundaries (named):**
- **no forward secrecy / per-message keys** at THIS layer — those are given by
  Double Ratchet (`node::ratchet`, below), seeded by this `root_key`;
- **directional authentication** Alice→Bob GIVEN an authentic IK_B (out of
  band/§12); NOT mutual. The long-lived prekey **is signed** (`prekey_sig`): XEd25519 on the
  SAME X25519 IK (Signal's XEdDSA — no second key, no safety-number change), covering
  `prekey_pub ‖ kem_ek ‖ M`. Handing out a ONE-TIME prekey is admission-gated
  (`FetchBundleOpk` — capability + quota, like a send): the plain public `FetchBundle` never
  carries one, because a public read with an irreversible side effect let sixteen anonymous
  fetches push every later first contact down to 3-DH (R2-3).
  Each ONE-TIME prekey carries its own signature too
  (`pqxdh::SignedOpk`, domain-separated), so a relay can neither substitute one of its own nor
  serve an unsigned one (CRYPTO-04). It CAN still withhold them and claim exhaustion — no
  signature distinguishes that from real exhaustion — which is why `Peer::connect` returns
  `ForwardSecrecy::{Full, NoOneTimePrekey}` instead of proceeding quietly.
  A sender rejects a bundle whose prekey / KEM key / mailbox point a
  relay substituted (`verify_prekey_sig`, enforced before a fetched bundle is used in
  `Peer::connect`), turning the old DoS-by-swap into fail-FAST. **Downgrade is handled:** an
  empty or wrong-length signature fails verification, so a stripped signature is REJECTED, not
  silently accepted. **Honest boundary:** even unsigned this was never a MITM/confidentiality
  hole — `root_key` includes `dh2 = EK_A × IK_B`, which the relay cannot derive, so a swap only
  ever made Bob compute a DIFFERENT key (silent delivery failure), never key recovery; the
  signature buys fail-fast + safe prekey rotation, not confidentiality. The XEdDSA primitive is
  the `xeddsa` crate — a REFERENCE, **unaudited** (not hand-rolled, not a second Ed25519 key).
  The one-time prekey is NOT signed (its swap is likewise only DoS, and it is consumed once);
- **one-time prekeys — COMPLETE end-to-end (three increments, 2026-07-17):** the initial
  agreement takes a fourth DH term `dh4 = EK_A × OPK_B` against a **consumed** one-time
  prekey, so a later compromise of the long-lived prekey secret no longer exposes the first
  message — the OPK secret it also depended on is deleted after one use. The three
  increments: (1) the key-agreement mechanism (`dh4` mixed in + bound in the transcript,
  the OPK consumed on accept); (2) the relay stores a published batch and hands out ONE
  distinct OPK per fetch (`opk_batches`, capped, exhaustion → 3-DH fallback); (3) the
  client persists the OPK secrets **inside the session state file** (`sessions.dat`,
  deliberately out of `account.key` so the identity is never at migration risk; they were a
  separate `opks.dat` sidecar until CRYPTO-26 needed the burn and the session it produces to
  commit in ONE rename) — `publish_with_opks` tops up and persists before publishing (under
  the sessions flock, since the file is now shared), `recv_session` reloads to accept and
  commits the remainder together with the new session.
  Pinned at every layer: `a_one_time_prekey_is_mixed_in_and_consumed_once`,
  `dh4_one_time_prekey_secret_is_load_bearing_in_root_key`,
  `the_relay_hands_a_distinct_one_time_prekey_to_each_fetcher`,
  `republishing_opks_never_hands_the_same_prekey_twice` (a keepalive republish must not
  stockpile duplicate OPKs on the relay — the client advertises only freshly minted keys),
  `one_time_prekeys_work_and_persist_across_the_process_per_call_client`;
- **no low-order/contributory check** of the three X25519 DHs — an audit item on
  this reference (not exploitable for the claimed property), the same guard as in
  fetch-auth;
- **1:1 only** — a group ratchet (MLS/TreeKEM) is another section.

## §2.1 Double Ratchet — per-message FS + PCS (`node::ratchet`)

A classical X25519 Double Ratchet (the Signal spec) over the PQXDH `root_key`.
§2.1: the ratchet is classical — post-quantum protection lives in the initial
PQXDH handshake, the ratchet adds per-message FS and compromise healing. A
session: `Session::init_sender(root_key, prekey_pub_B)` / `init_receiver(root_key,
prekey_B)`; `encrypt`/`decrypt`. `KDF_RK` = HKDF-SHA256(salt=rk, ikm=DH), `KDF_CK`
= HMAC constants (0x01 mk / 0x02 next-ck).
- **Forward secrecy as NON-RETENTION**: the message key is deleted after use,
  `KDF_CK` is one-way (you can't derive mk from next-ck). The load-bearing test
  `message_key_not_retained_in_session_state` — a dump of ALL the session's key
  material does not contain the spent mk. NOT "different keys" and NOT "replay
  fails" (that is replay protection) — precisely the absence of key material in
  the state.
- **Post-compromise security (healing)**: a DH step on a fresh ephemeral weaves a
  new DH into the `root_key`. White-box `fresh_dh_is_load_bearing_in_new_root_key`
  (like dh1/pq_shared in PQXDH): an adversary with the old rk but no new ephemeral
  will not derive the new root_key.
- **Transactionality** (a ratchet-specific "can't jam it"): `decrypt` checks AEAD
  BEFORE committing the chain (mutates a copy, commits on success). A corrupt
  packet is rejected AND the next valid one passes:
  `tampered_message_rejected_and_session_survives`.
- **Header-binding**: the ratchet pubkey/pn/n are bound into the AEAD AAD
  (`header_tampering_is_caught`). A fresh key per message → a zero nonce is safe.

**Crypto discipline:** the primitives are vendored (`x25519-dalek`/`hkdf`/`hmac`/
`chacha20poly1305`); the ratchet composition is **reference code** (the Signal
spec, like PQXDH/admission), **NOT audited**. NOT feature-gated (E2E is the core
of the product).

**Out-of-order tolerance (skipped message keys, the Signal spec):**
- a skip/reorder within a chain AND at the chain boundary is caught up: skipped
  `mk` are derived and stored, an out-of-order arrival (a mailbox batch, DTN
  store-and-forward — both real) is decrypted later
  (`out_of_order_within_chain_is_tolerated`, `reorder_across_ratchet_boundary_is_tolerated`).
  **Why now:** it used to be strictly in-order (one drop = a dead session forever),
  and the unconditional chain advance on `send` (nonce safety, below) ITSELF
  breeds gaps on a failed send — tolerance closes that liveness cost;
- a **double anti-DoS boundary**: `MAX_SKIP` (1000) per receive step against an
  unbounded KDF; `MAX_STORE` (2048 ≥ 2·MAX_SKIP) total with FIFO eviction against
  a memory/disk DoS (`gap_larger_than_max_skip_is_rejected_session_intact`);
- **compute-DoS amplification via trial-decryption (named)**: `peer` routes
  `Ratchet` by trying sessions, and a transactional decrypt derives skip-keys-and-
  discards on a miss → a forged message with `n`≈MAX_SKIP forces EVERY session to
  run up to 2·MAX_SKIP KDFs in staging: the cost ≈ N_sessions × MAX_SKIP per
  packet. Bounded (not unbounded), rate-limited by the admission layer above,
  legitimate traffic is cheap (small real `pn`/`n`). To tighten — a smaller
  per-path `MAX_SKIP` or sender-hinting of the routing; a next step;
- **a property ABOVE Signal (transactionality)**: `decrypt` mutates a copy and
  commits only on a valid AEAD — a forged high-`n` does NOT fill the store and does
  NOT move `nr` (in literal Signal, `SkipMessageKeys` mutates before DECRYPT).
  Discriminating: `forged_high_n_does_not_populate_skipped_store` (goes red on a
  commit before AEAD). The same protects trial-decryption in `peer`: a miss does
  not pollute another session's store;
- **the FS trade-off (named)**: skipped `mk` land at rest (in `SessionSnapshot` —
  otherwise they would not survive the client's `load→process→save`, making the
  fix useless), weakening FS-non-retention for EXACTLY those pending messages over
  the window "until received/evicted". The standard Signal trade-off; a time-based
  expiry (there is a `wall_clock`) would directly bound the window — a next step.
  Pinned by `skipped_key_survives_snapshot_restore` (mirrors the client path) + a
  `consumed` key is removed from the store (FS for consumed ones is intact);
- **no header-encryption** (the HE variant of Signal) — the header metadata
  (ratchet pubkey, numbers) is visible at this layer; closed by the §15 transport
  (Noise) below it;
- **memory zeroization** of message keys — the mk is dropped normally but not
  explicitly wiped (`zeroize`) — an audit hardening item; the non-retention
  property (not STORED in the state) does not depend on it;
- **woven into the in-process node path** via `node::peer` (below); the socket/CLI
  path is still a skeleton (needs session persistence);
- **1:1 only**.

## §2.1 session peer — the E2E of the message path (`node::peer`)

`Peer` connects PQXDH+ratchet to the REAL path (admission §7 → mailbox →
fetch-auth): `publish()` (its own bundle at the relay, §12) → `connect(peer_ik)`
(fetch the peer's bundle, the PQXDH initiator) → `send(peer_ik, pt)` →
`receive()`. There is also `connect_with_bundle` for OOB delivery/tests. One
bidirectional ratchet session per peer pair. The payload on the wire is the enum
`Payload::Session(SessionEnvelope)`; the first envelope is `Initial{ka, msg}`
(agreement + the first message), then `Ratchet(msg)`. The relay stores it opaquely.
Load-bearing: `bidirectional_multi_message_across_fetches` — multi-message in both
directions through a real mailbox with a batch fetch, the `Initial→Ratchet`
transition and a second send→fetch round continuing the same session (chains
survive fetches).
- **Unconditional chain advance** on `send` (nonce safety > liveness): each `mk`
  encrypts exactly one plaintext → a zero nonce is safe. A delivery failure = a
  **gap**, but it no longer jams the session (skipped keys, see `ratchet`):
  reordered (arriving later) — decrypts from the store, genuinely lost — leaves a
  slot-gap (eventually evicted FIFO), but subsequent traffic flows. This is NOT
  key reuse. A commit-only-on-`Accepted` would be a hole: another plaintext would
  take the same position → the same `mk`+zero nonce → keystream reuse (the relay
  is untrusted, the first ciphertext already left). Pinned by
  `failed_send_never_reuses_ratchet_position`. (Re-sending exactly the lost
  content is app-level: `send` again = a NEW position, not the same one; a
  reliability layer is separate.)
- **Routing `Ratchet` without a sender hint — trial-decryption** across all
  sessions; safe because `decrypt` is transactional (a miss does not move another
  session).

**Staged migration (not dead code):** `Payload` is the enum
`Skeleton(SkeletonSeal) | Session(SessionEnvelope)`. The session path is the new
in-process E2E; the skeleton still carries socket/CLI (`node::Client`/`Recipient`)
until session persistence is added there. The relay stores both variants opaquely.

**Boundaries (named):**
- **socket/CLI is ON this path** (persistence implemented):
  `Session::snapshot`/`restore` + `Peer::export_state`/`import_state`, saving under
  flock+atomic in `client::store` (see the client section). `karst send`/`recv` are
  entirely on §2.1;
- **§12 discovery is implemented** (`publish`/`connect` via the relay, see the
  section below); but the relay is NOT an identity anchor: the authenticity of
  `peer_ik` is out of band (an external wall);
- **first-delivery reliability is assumed**: the chain advances unconditionally
  (otherwise keystream reuse) → undelivered = a gap; only an `Initial` with n=0 can
  establish a session (first-delivery-must-succeed); a repeat `Initial` from a
  known peer does NOT re-establish a live session; retransmit-without-gap and
  prologue-repeat (Signal) are a separate reliability slice;
- **multi-peer `Ratchet` addressing** — currently trial-decryption (O(sessions));
  sealed-sender/session-id without metadata leakage is a separate slice;
- **1:1 only.**

## §12 discovery — publish/fetch prekey bundle (`node` + `peer`)

The relay stores published bundles by owner IK and serves them — eliminating "the
bundle out of band". `Peer::publish` puts its bundle; `Peer::connect(peer_ik)`
fetches the peer's bundle and initiates PQXDH. Wire: `PublishBundle`/`FetchBundle`
in `WireRequest`, travels inside the Noise session as send/fetch.
- **Writing is gated by an ownership proof** (`publish_proof`, the write-side
  mirror of `fetch_proof`): the publisher MACs the bundle under `DH(IK, relay)`,
  the relay checks it via `DH(relay, IK)`. It stops OTHER clients from overwriting
  someone else's bundle (a deliverability DoS). Plus a cookie gate (DoS/freshness)
  and a bounded `MAX_BUNDLES` (reject on full, not a silent drop). Load-bearing:
  `publish_requires_ik_ownership_proof` (a stranger cannot overwrite Bob's IK).
- **Reading is public** — a bundle is public material, no auth.

**The trust boundary is THE POINT (an external wall):** §12 is a discovery
mechanism, NOT an identity anchor. The relay stays untrusted for IDENTITY:
- a relay swapping **the IK itself** (IK_B→IK_M) → a full MITM, this layer does NOT
  catch it; only OOB/TOFU verification of the IK does. Pinned (executable-doc)
  `ik_swap_is_undetected_mitm_without_oob_verification`;
- swapping only **the prekey/KEM** (with an authentic IK) → the relay does not own
  IK_B/Alice's ephemeral → cannot compute root_key → **fail-closed**, no one
  decrypts. Pinned `swapped_prekey_bundle_fails_closed`. `connect` additionally
  checks that the returned bundle claims the REQUESTED IK.

**Presence oracle:** the public `FetchBundle` is a presence oracle: anyone can
confirm "IK X is registered on this relay" (lookup-by-IK, not enumeration — weaker
than enumeration). It is inherent to prekey distribution; for a private messenger
it is named explicitly — the registration metadata is visible to the
relay/observer.

**Implemented since:** signed prekeys (XEd25519 `prekey_sig` binds prekey↔IK, so a
prekey swap is now DETECTED, not only fail-closed) and one-time prekeys (§2.1).
**Deferred (named):** a capability gate on publishing and per-IK quotas (currently
cookie + ownership proof + a shared bounded cap).

## Linux desktop client (`impl/client`, CLI `karst`)

The first thing usable by hand: `karst init` (create an account — **prints the
12-word recovery phrase**), `karst restore <12 words>` (restore into an empty
`$KARST_HOME`), `karst show-phrase` (show your phrase), `karst id` (the skeleton
pubkey), `karst account` (the §2.1 IK — the address for discovery),
`karst dev-cap`/`import-cap` (a capability, which now names the relay it is FOR:
both take `--relay/--relay-id`, see CRYPTO-24 below), `karst publish --relay A --relay-id ID`
(§12: publish the §2.1 bundle), `karst send … --to HEX <msg>`, `karst recv …`
(+ optional `--socks5 HOST:PORT` through an external PT). The directory is
`$KARST_HOME` (or `~/.config/karst`). The identity is derived from the **root
phrase** (`client::seed`) — the same phrase gives the same IK on any device;
**losing the phrase = losing the account** (see the `client::seed` row). Verified
by an end-to-end e2e (a live `karst-relay`: a skeleton Alice→relay→Bob decrypted;
`init`→`restore` into a clean directory gives the same IK; reload-account→`publish`
over the socket; a wrong `--relay-id` → a hard error).

**§2.1 on the CLI — ENTIRELY.** `init`/`account`/`publish`/`send`/`recv` are all
on §2.1. `send --to <§2.1-IK>` establishes/resumes a ratchet session (the first
contact fetches the recipient's bundle, §12), `recv` advances the sessions. A
**persistent `Account`** (ik‖prekey‖KEM-seed, `create_new` 0600) + **persistent
sessions** (ratchet snapshots on disk between process invocations). Verified by
hand: two `KARST_HOME`s through a live relay — Alice sends 2 (Initial then Ratchet
from the saved session), Bob decrypted both and replied, Alice received it
(bidirectional on one persistent session).

**Keystream reuse is closed along TWO axes** (otherwise two texts under one
`mk`+zero nonce; the relay is untrusted, the ciphertext is already there).
- *Concurrency axis:* `send`/`recv` hold an **exclusive flock** (`sessions.lock` —
  a DEDICATED file, not renamed) over the whole window load→operation→save.
  Without it, two `karst send`s would take position N in parallel. `sessions.dat`
  is written **atomically** (temp→fsync→rename; a lock on the renamed file would
  hang on the detached inode — worked around with a dedicated lock file).
  Load-bearing: `concurrent_sends_under_lock_never_reuse_ratchet_position` (2×25;
  without the lock it fails — verified by neutering).
- *Crash axis:* `send_session` = encrypt(advance) → **save BEFORE transmit** →
  transmit → save(cleanup). Position N is durable BEFORE `ct_N` appears on the
  wire; a crash between transmit and save → the message is lost (a gap), but N is
  not reused. Save-after-transmit would leave a window to repeat a position.
  Load-bearing: `crash_between_transmit_and_save_never_reuses_position` (without
  pre-save it fails — verified by neutering).

**A session snapshot** = the ratchet chain/root keys + the private ratchet key +
the cookie + the nonce counter. **NO per-message `mk`** (they are local →
FS-non-retention is intact). Explicit serde (not a blanket one on `Identity`) —
each secret to disk is deliberate.

**At-most-once on receive (named):** `recv` = fetch→process→**save**→print; the
mailbox is drained at the relay, the snapshot lands BEFORE display. A crash between
fetch and save loses those messages (the relay already deleted them) — ack-based
retention is deferred.

**At-rest encryption — IMPLEMENTED (`client::secretbox` + `store`).** `identity.key`,
`account.key`, `sessions.dat` are encrypted with `Argon2id(KARST_PASSPHRASE, salt)`
→ `XChaCha20-Poly1305` (a fresh random 24-B nonce on EVERY write — critical, since
`sessions.dat` is overwritten on each operation under a fixed key; a repeated nonce
= keystream reuse). The key is derived ONCE per process. Format `MAGIC‖nonce‖AEAD`;
a foreign prefix → "re-init needed" (no auto-migration). `unlock` checks the
passphrase with a verifier (a sealed constant) — a wrong passphrase is rejected
IMMEDIATELY, before any write (otherwise `init` with a typo would save files under
different keys). identity/account/**capability**/sessions are encrypted (capability
too — `import-cap` also accepts a real admission credential).
- **What it protects — only the COLD disk** (a stolen laptop, a backup, a synced
  `~/.config`). **NOT the hot process**: the env passphrase is readable from
  `/proc/<pid>/environ` of a live host → this does NOT close the hole "a live
  receiving chain on disk" under a HOT compromise. We claim cold-disk, no more.
- **Not covered (named):** the relay keys (`relay.key` — the server restarts
  unattended, encryption would regress that; its own trust boundary / KMS — out of
  scope); an interactive no-echo prompt (currently env only); zeroize of the
  derived key and the decrypted secrets in memory (the same class as zeroize of
  message keys).

The lib/bin split: `client` (lib) — persistence + orchestration with no
stdout/args, so the core can be reused by Android via JNI (the JNI itself is not
here); `karst` (bin) — only argument parsing and output.

**The first time a private key touches disk** — discipline in `store`: the file is
created IMMEDIATELY under 0600 (not write-then-chmod), identity is NOT overwritten
(`create_new` — an overwrite would kill access to everything sealed under the old
key; `init` is idempotent). Load-bearing:
`alice_sends_bob_reloads_from_disk_and_decrypts` — Bob's identity is saved and
RELOADED from disk before receiving (otherwise the test would not touch
persistence); plus `store_identity_roundtrip` (incl. rejection of an overwrite).

### Fetch-auth (§7 mailbox ownership) — off-path drain closed (on-path replay → §15)

Previously `Fetch(pubkey)` bypassed the pipeline: with no cookie/proof, anyone who
knew the address-pubkey drained someone else's queue (a silent DoS).
Now a fetch:
1. goes through the **cookie handshake** (a DoS gate + 30 s freshness, like send);
2. carries a **proof of ownership** of the mailbox private key: `proof =
   HMAC(HKDF(X25519(id_sec, relay_pub)), cookie.mac ‖ mailbox_pub)`. The node
   verifies it by computing the same static-static DH on its side
   (`X25519(relay_sec, mailbox_pub)` — the symmetry of X25519). Only the holder of
   the mailbox private key computes the DH → the proof. A failure → `Reject`, the
   **mailbox is NOT drained**.

The node was given a static key (`relay_public()`, printed by the binary; it is
needed anyway for §12/§15). The KDF domain `KARST-fetch-auth-v1` is separated from
seal (`KARST-skeleton-seal-v1`) — the same domain-separation principle.
Load-bearing: `attacker_knowing_pubkey_cannot_drain_mailbox` — it checks that a
foreign fetch is rejected AND **the message remains** (not only the response code).
A cookie refresh on fetch as on send. `recv` now distinguishes "empty" (`Ok([])`)
from "unavailable / auth denied" (`Err`).

**Residual risks:**
- **on-path replay — CLOSED by Noise (§15).** cookie+proof now go inside the
  encrypted per-session session → an interceptor can neither read nor replay them.
  (Later — bind fetch-auth to the Noise handshake hash for full session binding;
  not in this slice.);
- the node keys (fetch-auth + Noise-static) are **PERSISTENT** — `karst-relay`
  stores them in `$KARST_RELAY_HOME/relay.key` (0600, `create_new`), the relay-id
  is stable across restarts. The Noise pair is persisted whole (priv+pub — we don't
  rely on deriving pub from priv matching). Verified: restart → the same relay-id +
  a working handshake (`relay_with_fixed_noise_key_handshakes` + a CLI e2e). **Not
  persisted:** the mailboxes and the published bundles (in-memory — lost on restart;
  the client re-publishes/re-sends) — a separate slice. The cookie keys are
  ephemeral by design (rotation by epochs, no effect on the relay-id);
- the identity key is in TWO DHs (seal — ephemeral-static; fetch-auth —
  static-static); the domains are separated at the KDF level.

**Honest client boundaries (named, not hidden):**
- **sender authentication EXISTS** (§2.1 PQXDH) and is **surfaced**:
  `receive`/`recv_session` return `Received { sender, plaintext }`, `recv` prints
  `[IK-prefix…] text`. Attribution: an Initial carries the IK in the KA, a Ratchet
  — by the session that decrypted (`receive_attributes_sender_across_two_peers`);
- **at-most-once on receive:** `fetch` drains the mailbox (remove) — a
  crash/failed decryption after a successful fetch loses those messages;
- **at-rest encryption EXISTS** — identity/account/sessions under
  `Argon2id`+`XChaCha20-Poly1305` (`KARST_PASSPHRASE`); protects the COLD disk,
  not the hot process (the env passphrase is readable from `/proc`);
- **a dev capability with a public secret** (`[0x33;32]`) — local testing only; a
  real capability issuance from an issuer (§7.2) is a separate layer.

## Desktop GUI — the legacy egui client (`impl/gui`) was REMOVED (2026-07-27)

The egui/eframe client is gone: the crate, its `karst-gui` binary, its 36-test
`worker_e2e` suite and `scripts/karst-gui.sh` were deleted and the workspace member
dropped. The **Tauri desktop** (`impl/desktop`) is the only GUI.

Why: two UIs meant two orchestration paths and two sets of integration tests, so a fix
in one could (and did) sit unfixed in the other. It also pulled the whole
eframe→winit→wayland-scanner→quick-xml chain into the tree, which is where both open
RustSec advisories (RUSTSEC-2026-0194/0195) came from — removing it closes them.

**Honest consequence, and what was done about it:** those 36 worker tests exercised the
legacy client's own worker, so they retired with the code they tested — but three
behaviours were only ever covered end-to-end THERE. Those are now pinned at the `client`
layer, where the logic actually lives and which the desktop reuses verbatim:
`an_expiring_message_is_delivered_but_never_persisted`,
`delete_for_everyone_reaches_the_peer_with_the_shared_timestamp`, and
`clearing_a_chat_wipes_it_from_disk_across_a_reload`. The broader point stands: the
shipping Tauri client still has almost no e2e tests of its own.

## Calls (§21) — NOT implemented (honestly)

There are **no** voice/video calls, and there won't be in this repository without
a separate large effort. This is not "polishing the messenger" but a whole
REAL-TIME subsystem, orthogonal to the store-and-forward message path:

- **The media plane** (not here at all): audio capture from the device, a codec
  (Opus), a jitter buffer, echo cancellation; for video — a camera + VP8/AV1. It
  requires hardware (mic/camera) and low latency — fundamentally NOT verifiable in
  this headless sandbox (no audio devices, no second live peer for a media loop).
- **NAT traversal / path establishment**: ICE/STUN/TURN — a direct P2P connection
  between clients behind NAT. The current transport is client→relay (mailbox), NOT
  client↔client; calls require a different path.
- **Media crypto**: SRTP/DTLS or ratchet-over-media — its own key model over the
  §2.1 handshake.
- **Signaling**: offer/answer/ICE candidates — this is the ONLY thing that would
  land on the existing `content` envelope (another message-type branch). But
  without a media plane, signaling doesn't "call" anything, so empty signaling
  code is NOT added now (we don't pass off a stub as a feature).

**The right order, if taken on:** a WebRTC stack (e.g. `webrtc-rs`) for the media
+ ICE → signaling over `content` → key integration with §2.1. This is comparable
to the Android client in size and just as weakly verifiable here — so it is named
as an explicit not-done item, not a stub.

## Known open spots (not walls, but honest limitations)

- `max_hops` in DTN is advisory (cryptographically unenforceable in an
  opportunistic mesh).
- Placeholder parameters (e.g. `MAX_DTN_TRANSIT_TTL` 7 days) need calibration.

## Closed gaps

- **Capability quota enforced + anti-replay across the epoch boundary.**
  `CapabilityQuotaTracker` (§7.2) keeps a per-capability sliding `window_secs`
  window: it enforces `max_requests`/`max_bytes` and catches a verbatim replay by
  `proof.mac` (stable on a replay of a captured proof, including across the epoch
  boundary — where the epoch-scoped Stage-3 filter is powerless). Consume — only
  after a successful MAC (a bad proof would not burn someone else's quota).
  Previously a captured `(nonce, proof)` was reused once in each new epoch until
  `not_after`; now it is bounded by `max_requests` per window. Test
  `captured_proof_replay_caught_across_epoch`. An epoch-freshness check (as in RLN)
  must NOT be added here — the capability is deliberately multi-epoch (the role of
  `not_before/not_after`).

## Build and tests

```sh
cd impl
cargo test                                    # the whole workspace
cargo test --features unaudited-crypto        # + tring and its e2e
cargo run -p node --bin karst-relay 127.0.0.1:9000   # the skeleton relay (not production)
cargo clippy --workspace --all-targets --features unaudited-crypto
KARST_REGEN_VECTORS=1 cargo test conformance_vectors_match_frozen  # update the vectors

# The CLI client (at-rest: needs KARST_PASSPHRASE):
KARST_PASSPHRASE=... cargo run -p client --bin karst -- init
# The desktop GUI (needs an X11/Wayland display — won't start headless):
cargo run -p desktop --bin karst-desktop
```

`admission/tests/vectors.json` — frozen conformance vectors (§14): a byte-for-byte
reference for a second, independent implementation.

## PIR (plan slice 5): the composition holds, the available crypto does not — measured 2026-07-17

Slice 5 was scoped as "PIR for the stranger's first knock", then audit widened its remit:
it is also the only honest answer to slice 2's epoch-chaining gap, because the defect is
that a fetch reveals WHICH box is read. Two questions had to be answered before writing
any of it. The first passed. The second did not.

### 1. Does PIR fit the architecture? YES — and it is now a test

PIR's premise is that the client does not name the box, so the ownership proof
(`DH(relay_identity, mailbox)`) cannot run and PIR by construction lets a client retrieve
any slot. **PIR therefore deletes the access control fetch-auth provides.**

That turns out to be survivable, because fetch-auth was never providing confidentiality.
Every payload is already sealed to its recipient — ratchet ciphertext, or a `SkeletonSeal`
addressed to their identity key — so a slot read by a stranger is bytes they cannot open.
What fetch-auth actually protects is DELETION: a fetch DRAINS, so without the proof anyone
knowing your address could throw your mail away. That is availability, and under PIR the
attack is structurally impossible: you cannot target what you cannot name.

Pinned by `a_mailbox_payload_is_useless_to_anyone_but_its_recipient`. If it ever reddens,
PIR does not fit and the architecture is wrong rather than the crypto.

**Ripples, named:** no delete-on-read means mail persists to TTL, so the sweep becomes the
only GC and the mailbox-growth/DoS posture changes; and fetch quota/replay currently key
on a named mailbox, which has no name under PIR.

### 2. Is there usable single-server PIR? NOT for a mailbox — measured, not guessed

Information-theoretic PIR is cheaper but needs ≥2 non-colluding servers — precisely the
"other people's honesty" bill the thesis rejects. So single-server computational PIR is
the only candidate, and its bill is CPU, which we can pay.

`ChalametPIR` (FrodoPIR family, single-server, key-value, LWE — exactly our shape) was
measured directly rather than assessed from its README:

| DB size | `Server::setup` | Client hint |
|---|---|---|
| 64 slots | 22 ms | **4.6 MB** |
| 512 slots | 232 ms | **5.0 MB** |
| 4096 slots | 5.6 s | **5.5 MB** |

**The hint is ~5 MB and is a function of the database CONTENT** (`hint = A × D`). It is
nearly independent of how many slots there are — it is driven by the LWE dimension — and
it is invalidated by **every single deposit**. This whole preprocessing family assumes a
slowly-changing database: a breach list, a CRL, a block index. A live mailbox is the
opposite — it changes on every message. Amortising the hint over many queries is the
scheme's core bargain, and a mailbox never holds still long enough to collect.

Rebuilding on a schedule does not rescue it: at one snapshot per 10 minutes every client
downloads ~5 MB per snapshot (~720 MB/day, over Tor), and mail is undeliverable until the
next rebuild — which contradicts the hot window's entire purpose.

**So slice 5 as scoped is a research project, not a slice**, and saying so is cheaper than
discovering it three weeks in.

### What the measurement actually points at

The failure is specific to CLIENT-side preprocessing, not to PIR. The family that fits a
changing database does its preprocessing server-side and takes an encrypted query per
request — the client stores no hint, and the server pays O(N) homomorphic work per query.
That is the inverted cost curve the thesis already likes: cheapest on a SMALL relay.

- **Spiral** (`spiral-rs`) — the right family; the Rust implementation is `0.2.1-alpha`.
- **Oblivious Message Retrieval** (`ecdh-omr`) — literally this problem stated as a
  primitive: retrieve your messages from a bulletin board without revealing which are
  yours. Research-grade.

Both are alpha/research code. Per the `tring` precedent, anything of this class ships
feature-gated behind `unaudited-crypto` with a pin asserting the stub is not real PIR —
never hand-rolled lattice crypto that merely looks finished.

**Status: slice 5 is BLOCKED on an external wall** (usable single-server PIR/OMR in Rust),
which is the same class of wall as the RLN zk circuit and the threshold-ring audit. The
`known_gap_the_relay_can_still_chain_epochs_through_the_overlap` pin stays red-in-waiting
until it is climbed.

## Network shape: Public / Private nodes — design settled 2026-07-17

A long design discussion (recorded here so the reasoning is not lost) settled how KARST
becomes a *network* without becoming a *federation*. The full statement lives in
[ROADMAP.md](ROADMAP.md) under "The network shape"; this is the STATUS-side record of the
decisions and the honest residuals, since the code is the source of truth.

**Built so far of the Public tier: the DOOR (slice 4a, PoW → capability).**
`KARST_RELAY_MODE=public` runs a PoW-gated open door — a client EARNS a capability by
hashcash (`karst join`), the per-capability quota bounds it, and the capability is
**stateless** (recomputed from an issuer key derived from the node key, `pow_cap_secret`),
so it survives restarts and there is no table to fill. This is the spam **bound** that makes
a public relay runnable without "trust the internet not to flood it"; it is NOT Sybil
resistance (difficulty is a speed bump — see ROADMAP 4a).

**Also built: node-list discovery + gossip** (which relays exist; verify-before-add — see the
node-list section) and **opt-in discovery via a contact code (slice 4c, single-relay)** —
`node/src/discovery.rs`. A user who wants to be findable publishes a `DiscoveryRecord` under
`discovery_pseudonym(discovery_pub)`, where `discovery_pub` is a **RANDOM per-user key decoupled
from the IK** — so the code is unguessable (no dictionary/username to brute-force), **rotatable**
(a new keypair mints a new code and retires the old, IK untouched, existing contacts unaffected)
and **revocable** (delete/expiry), all WITHOUT changing the permanent identity. There are
deliberately **no chooseable usernames** — a chooseable name is a squattable global namespace; a
random code is not. Two signatures protect a record: an **IK signature** over
`(discovery_pub, ik, location_id, expiry)` so a resolver trusts the code→IK binding without the
relay vouching (`verify_binding`), and a **discovery-key write signature** so only the code's
owner can create/rotate/delete its slot. Records carry a TTL (`DEFAULT_TTL_SECS`, capped at
`MAX_TTL_SECS`) and are dropped lazily on lookup. **Key property vs. the previous design:**
discovery is NEVER a side-effect of a bundle publish — being *reachable* no longer leaks
fact-of-participation into a lookup-able directory; you are only findable if you explicitly opt
in. CLI: `karst discovery on|rotate|off|status` + `karst find <CODE>`; a future maintainer MUST
keep the write path self-authenticated (discovery-key sig) and MUST NOT re-introduce an IK-keyed
or always-on directory entry. Residuals: the lookup is not private (the relay sees the pseudonym
queried — mailbox-PIR is walled), the relay could withhold or stale a record (an availability
attack, not a MITM — identity stays anchored on the IK the resolver verifies), and anyone holding
your code can confirm you are enrolled (the fact-of-participation floor, now scoped to a code you
chose to hand out rather than to your permanent identity).

**Still NOT built:** discovery REPLICATION across nodes (a single relay serves the record today;
cross-node findability needs the record gossiped + a freshness rule so a newer location supersedes
a stale one — the TTL + expiry in `DiscoveryRecord` are the hook, but the replication/merge and
its anti-rollback are not written) and PIR (walled). The primitives the whole tier rides
(sealing, drop-boxes, per-handle isolation, the blob buffer, `RouteOffer`) are all in.

### The one invariant everything rests on

**Delivery is client-direct; nodes never forward each other's messages.** The client is
the bridge, not the infrastructure — you reach someone by learning which node they are on
and connecting there directly, exactly as a browser goes where a URL points. Relay-to-relay
forwarding was rejected every time it resurfaced because it is transitive exposure (trap
#1): a forwarding node learns metadata about users it does not host, bypasses the
destination's admission, and — full mesh — caps write-throughput at one node. Content
encryption does not fix this; the leak is who-talks-to-whom at the network layer.

Discovery and delivery are therefore separate planes: discovery (which nodes exist, where
a user is) MAY be shared between nodes; delivery MUST NOT.

### Two roles, one binary

- **Public:** listed in a replicated **blinded** directory, open door (PoW pass),
  anyone can find and message you (client connects directly). Knows only about other
  Public nodes. The high-throughput tier — and it scales *because* nodes do not forward:
  each serves its own users, so adding nodes adds capacity. Directory replication buys
  universal findability + resilience, a different mechanism from throughput.
- **Private:** no directory, invite-only, reachable only by people you brought
  in. **Only its users know it exists.**

**Public ⊥ Private, and it holds mechanically:** a Private node is in no directory, so
Public nodes cannot learn it; and a Public→Private migration invite (`RouteOffer`) is
sealed E2E content, so a Public node relaying it sees opaque bytes, not the Private
address. Residual: a Public node can notice a conversation go quiet and infer *that* a
migration happened, never *where*.

### The privacy gradient (settings, not modes)

One identity moves along it: (1) Public stable identity — findable, convenient, content
private, graph-edge residual at scale; (2) migrate marked contacts to your own Private
node, so the rendezvous leaves the shared relay and your graph fragments across your
contacts' Private nodes; (3) different contacts on different nodes of yours — inbound
compartments;
(4) not in the directory at all, OOB one-time invite addresses — led to, never found.
Carrier of a self-run node is the operator's choice; **Tor is not forced** (often a
bigger traffic-classification trigger, not universally more private — a correction of an earlier Tor bias in
this doc's author).

### Sybil / burners, resolved

Disposable requester accounts (so a stable identity never touches a relationship) need
cheap creation — which spam needs too. Resolution: **paranoia pays for itself** via a
**PoW** creation gate (anonymous, no trail — unlike payment/invite gates that would
relink the burners they hide) plus the existing per-capability quota. One mechanism is
the Public door, the spam gate, and the burner price. The fully-anonymous *rate-limited*
ideal is RLN (external wall); the practical PoW→capability→quota gate needs no RLN and is
buildable now.

### Two thesis-level forks, named not built

- **Federation** (message forwarding). Trap #1. Not built.
- **Minted rewards** (registration or storage). A minted reward pays for the attack the
  door stops (operator farms fake registrations; storage node claims dropped files),
  needs a token (KARST is stated *non-commercial*; consensus is an "other people's
  honesty" bill), and for storage needs proof-of-storage — the core of Filecoin/Sia.
  **Conserved** payment (registrant pays their host; a node charges its own users; mission
  operators) is fine and cannot be farmed. Incentive must come from the operator's own
  benefit, never a global minted pool.

### File transfer is already the right shape

`node/src/blobstore.rs`: disk-backed, encrypted, TTL-swept (7 days), hard-capped, reject
-when-full. The relay is a **transient buffer**; files live durably on endpoint devices,
like the mailbox holds messages transiently. No storage-node role or reward is needed for
*transfer*. Permanent hosting is a separate product and the same fork as minted rewards.
Cheap improvement worth a slice: drop a blob on successful fetch, TTL only as the fallback.

### Loose ends captured from the design discussion (so they are not lost)

Four smaller conclusions the discussion reached that belong in the record:

- **The two roles are independent — either works alone.** A Public-only world is a
  complete, ordinary findable messenger; Private is opt-in, never required. A Private-only
  world is Private nodes with no public discovery (reach by invite/OOB only). A single node of
  either kind already works for whoever is on it. The only real precondition for A↔B is a
  **shared rendezvous node both can reach** — Public gives it via the directory, Private
  via an invite. Neither role is load-bearing for the other. (This is the answer to "does
  it work with zero Private nodes": yes, and that is the baseline.)

- **Node discovery bootstraps from a node-list, and that is cheap.** A new node learns of
  others from a **list of relays** — handed over by any node you already know, gossiped
  between Public nodes. This is fine because relays are **public infrastructure**: the list
  is "which relays exist", not "which users exist". It must not be confused with the *user*
  directory, which is the sensitive, blinded one. The node-list is the blockable seed
  (same property as any bootstrap), addressed by carrier diversity, not by hiding it.
  **Built (operator-curated foundation):** `RelayDescriptor {noise_pub, fetch_pub, addrs}`,
  wire `GetNodeList`→`NodeList` (public read, rides the Noise session, bounded), served from
  `RelayNode.known_relays` seeded with **self + `KARST_RELAY_PEERS`** (self only if
  `KARST_RELAY_ADVERTISE`/listen addr is routable — never 0.0.0.0/loopback). Client:
  `karst relays`. **NOT yet built — peer-to-peer gossip merge**, because re-serving an address
  heard from a peer without dialing it first is a reflection/DDoS-amplifier (any relay could
  aim every client at a victim IP); that slice needs **verify-before-add** (dial + handshake
  match its `noise_pub`) plus per-source/per-address rate limits, and is deliberately separate.
  A descriptor self-authenticates on dial, so a wrong-key entry only wastes a connection.
  **Peer-to-peer GOSSIP MERGE now built (`node/src/gossip.rs`):** a relay with configured
  `KARST_RELAY_PEERS` runs a background round every `GOSSIP_INTERVAL_SECS`, pulls each peer's
  `NodeList`, and merges newly-heard descriptors ONLY after **verify-before-add** — it dials the
  address and confirms (a) the Noise handshake matches the claimed `noise_pub` and (b) the relay
  there advertises ITSELF with the same full relay-id (`noise_pub`+`fetch_pub`), so a peer can
  neither point everyone at a victim IP (the handshake fails) nor lie about a real relay's fetch
  key. Rate-limited three ways: per-source (`MAX_NEW_FROM_ONE_PEER`), per-address (each address
  dialed at most once per round, so N junk entries at one IP cost ONE dial), and overall
  (`MAX_DIALS_PER_ROUND`). Self is seeded FIRST so it always survives the frame trim and stays
  verifiable. The CLIENT side honours verify-before-add too now: `client::import_discovered_relays`
  (`karst relays --add`) fetches a relay's node-list and adds a discovered relay to this account's
  multi-homing secondaries (`extra_relays.dat`) ONLY after dialing it and confirming it serves its
  own full relay-id — so a client never routes its mail through a relay it hasn't confirmed.
  **CRYPTO-23 — the client also no longer stores the address the gossiping peer supplied.**
  Dialing proves who answers, not that the *address* belongs to them: a transparent TCP/WSS proxy
  in front of an honest relay passes the handshake (it terminates at the real relay) while the
  client persists the proxy as its route — a permanent vantage point on IP, timing, volume and a
  selective-drop switch, with Noise intact. `verified_self_address` therefore uses the peer's
  address only as a place to DIAL and stores an address out of the relay's own authenticated
  self-descriptor (re-checked against the SSRF gate). Deliberately NOT the audit's suggested
  "compare the hint against the self-descriptor": address comparison needs canonicalization rules
  (host vs IP, carrier, port, path) and every such rule also refuses honest relays reached by a
  different spelling. **Residual, node side (`gossip::gossip_round`, out of this change's scope):
  a relay merging a heard descriptor still verifies with, and re-serves, the peer-supplied
  addresses — so a hostile peer can still inject a proxy address into other relays' node-lists.
  The client no longer adopts it as a route, but the class is only half dead until `gossip_round`
  keeps the self-declared addresses too.** Any FUTURE auto-dial path must reuse the same gate.

- **The relay does NOT automatically reconstruct your whole graph — a precision that
  corrects an earlier overstatement in this doc.** Post-3b, what a Public node sees cleanly
  is the individual conversation **edge**: one drop-box, deposited by one end, fetched by
  the other, pseudonymously. Assembling your *separate* edges into your full contact set
  (proving two endpoints are the same person) is NOT free — per-handle isolation breaks the
  source-address link and rotation breaks the address link, so it takes **timing
  correlation** of your polls, which Poisson cadence + cover + isolation partially defend.
  So the honest residual on a busy Public node is "edges leak, pseudonymously; full-graph
  assembly is a defended timing attack", not "the relay has your social graph". The
  irreducible core is the single edge at the rendezvous — only mailbox-PIR (walled) or
  broadcast (affordable only small) removes it.

- **Decoy knocks were proposed, then SUPERSEDED by disposable-account knocking — recorded
  as rejected, not a live tool.** The idea: when first-contacting A, also knock on N random
  directory entries to dilute which contact is real. It hides the *target* end of the edge
  but (a) **spams N real users** unless the directory is blinded, conflicting with the spam
  goal; (b) dilutes only *first-contact* — the ongoing edge re-emerges because decoys have
  no follow-through, so holding the dilution means sustaining N fake conversations forever.
  The **disposable-account-per-knock** approach (see the Sybil paragraph above) replaces it
  for the purpose that mattered: it hides the *source* end — one real knock from a PoW-gated
  burner, so the relay cannot link your knocks to each other or to you — with **no spam and
  nothing to sustain**. Decoys would only additionally muddy A's *inbound* set, which is the
  inherent price of A being findable and which a burner does not remove either. So the
  adopted mechanism is the burner; decoys are not needed and not planned.
