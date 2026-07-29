# Proxy identity — a root with no address, reached only through disposable channels

**Status: DESIGN. Phase 1 (per-proxy random secret; see #207 below) in progress; nothing here is
shipped yet.**
This document is the authoritative description of the model so the code, the roadmap,
and the honesty in the UI stay aligned as it is built. Source of truth is the code; when
they disagree, fix this doc.

## The problem this fixes

Until now a KARST identity **is** its identity key (IK): the IK is your permanent address,
the thing you hand out, the thing a contact code resolves to, and the thing every session,
publication and channel is keyed on. That has a structural flaw the model below removes:

- **The IK cannot be changed.** It is derived (frozen) from your 24-word phrase — it *is* your
  identity to every existing contact. So you cannot "change your primary address."
- **Any way to reach you leaks the permanent IK.** A resolved contact code, a shared address,
  a one-time invite — all hand over the forever-IK. Whoever got it has it for good.
- Therefore **one leaked or abused address = permanent exposure**: spam, or a hostile party who
  can always find you, with no escape short of abandoning the identity your contacts know.

"One-time" codes (shipped in [discovery](../../impl/README.md), PR e232ccf) only limit *who*
resolves — they still hand over the permanent IK, so the one-time property is largely defeated.
This model is the real fix.

## The model

**The root has no IK and no network presence.** What the recovery phrase + device password
unlock is a *seed*: the HD-derivation root and the single local hub that owns all your data. It
never publishes a bundle, never joins a session, has no address. There is nothing to leak,
because the primary identity is not a network object at all — *you cannot expose what does not
exist on the wire.*

**Connection accounts ("proxies") are the only network objects — and a proxy is just a
communication channel, not a persona.** A proxy carries only:

- a **random 32-byte secret**, minted (`OsRng`) once when the proxy is created, and the
  **keypair** derived from that secret (its IK is the address a contact uses to reach you) — see
  "Proxy derivation and destruction" below,
- its own **prekey / bundle / one-time-prekey state** on the relay,
- a **label**.

Nothing else. A proxy has no contacts, no profile, no feed of its own — making it a full persona
would duplicate all your data across every proxy, which is exactly wrong. Proxies are disposable:
you hand a proxy's address (or a code that points to it) to a contact or a group, and you rotate
or burn it freely. Burning a proxy kills that channel; the root and every other proxy are
untouched.

**The root owns all data, one copy.** Profile, avatar, contacts, every conversation (one unified
inbox), the feed — all live once, at the root. Attachment without duplication:

- a **contact** record (root) is tagged with *which proxy* reaches it;
- a **session / history** is stored at the root, tagged with its proxy, while the cryptographic
  ratchet uses that proxy's keys;
- **profile / avatar** are the root's — shown *over* a channel when you choose, never copied;
- a **publication** is the root's and fans out to each contact **through the proxy that contact
  knows**, so a contact sees the post coming from the identity they talk to.

Incoming mail to any proxy is routed to the single root inbox; you reply *from* the proxy the
contact knows. Spam is handled at the channel level — reject a contact request, block an accepted
contact, or rotate the whole proxy — never by changing your identity.

## Proxy derivation and destruction (#207, A6-4)

**A proxy's keys come from a random per-proxy secret, never from the phrase.** An earlier version
of this design derived proxies as deterministic HD children of the phrase
(`proxy_n = HKDF-Expand(PRK, info = "KARST-proxy-derive-v1" ‖ le32(n))`, on a domain separate from
the frozen root `derive`). That was wrong: "burning" a proxy only flipped an `active` flag in the
registry, so the phrase alone could still regenerate ANY past proxy's private keys forever — match
them against historical relay logs, enumerate proxies never even created yet, and link identities
the UI presented as independently destroyed. Burn was an operational label, not erasure.

The fix, now shipped in `Store`/`seed.rs`:

```text
secret         = OsRng() — 32 random bytes, minted ONCE when the proxy is created
proxy_identity = HKDF-Expand(HKDF-Extract(salt=∅, ikm=secret), info = "KARST-proxy-secret-derive-v1")
```

The `secret` lives ONLY inside the sealed proxy registry (`proxies.dat`, `ProxyEntry::secret`) —
it is never derived from, or storable back into, the recovery phrase. Consequences:

- **Burning a proxy DELETES its registry entry, secret included.** This is not reversible: once
  the secret is gone, nothing — not the recovery phrase, not the device password, nobody —  can
  reproduce that identity's keys again. That irreversibility is the fix, not a side effect.
- **The phrase recovers the ROOT identity, not its proxies — and never the vault data either.**
  Entering the 24 words on any device re-derives the SAME root `seal`/`account` (as always — this
  is unchanged by #207), which is all the phrase ever gave you. Contacts, history, feed and the
  proxy registry itself are vault DATA, encrypted at rest under the device password, not the
  phrase — recovering the phrase alone was never a way to get that data back, on a new device you
  provision a fresh, empty vault. What #207 changes is narrower and specific to proxies: even if
  you DO still have the old vault (same device, forgot nothing), a burned proxy's keys are gone —
  the vault's own copy of the secret was deleted, and the phrase was never able to reproduce it
  either way. So "recoverable, no extra backup" (which described the *old*, phrase-derived proxy
  keys) no longer applies to proxies at all: a restore flow must mint fresh proxies and
  re-establish channels with contacts out of band; it cannot regenerate the old ones from anything.
- **The proxy `index` is still a stable, monotonically-increasing identifier** — it namespaces a
  proxy's on-disk network files (`sessions.p<index>.dat`, `opks.p<index>.dat`, …) and tags
  contacts with which proxy reaches them, but it plays no role in deriving keys, and burned
  indices are never reissued (reusing one would let a freshly-minted proxy inherit a burned
  identity's leftover session/OPK files and contact tags).
- **No conformance vector is pinned for the secret→identity derivation.** Unlike the root's
  `frozen_derivation_vector`, there is nothing here that a phrase-holder wrote down and would be
  orphaned by a future change — the secret itself is the only backup, and it lives only in
  whatever `proxies.dat` says right now.

## Honest limits (these must be surfaced in the UI, not just here)

1. **Network-level clustering.** A proxy hides the root from *contacts*, but a relay that serves
   the mailboxes of several of your proxies over one connection / IP can **cluster your proxies
   with each other** (not with a root IK — there is none — but with each other and your network
   location) from fetch patterns and timing. Breaking that requires each proxy on its own circuit
   (Tor / bridge). Same class as "the relay sees who resolves a code."
2. **Profile-level linkability is a separate axis.** If you present the *same* root profile /
   avatar over every proxy, contacts who compare notes can link your proxies by the shared
   profile. Proxies give **network-level** rotation and disposal; profile-level unlinkability is a
   deliberate per-channel choice (the default is that people you *accept* see your profile — they
   already know it is you). The data model does not duplicate either way.
3. **Recovery gives you the root's network identity back, nothing else — and now not even proxy
   keys (#207).** The phrase only ever re-derives the root `seal`/`account`; vault data (profile,
   contacts, history, feed, the proxy registry) is a separate, device-password-encrypted thing the
   phrase never touched. What changed: proxy identities used to ALSO be phrase-derived (by HD
   index), so even without the old vault you could regenerate a proxy's keys from the 24 words
   alone. Now each proxy's keys come from a random secret that lives only inside that
   device-encrypted registry, so losing the vault (or burning the entry) loses the proxy for good —
   the phrase was never, and is not now, a backup for it. Restoring an account (new device, phrase
   only) means *zero proxies*: every channel must be re-created and every contact re-established
   out of band. Say exactly that in the restore UI — do not imply proxies come back with the phrase.
4. **Whoever you accept learns that proxy's IK** — it is unavoidable for E2E — but it is a
   disposable proxy IK, not your identity, and it is per-channel revocable.
5. **Continuity across rotation costs a re-handshake.** With no stable public identity there is no
   way to *prove* "it is still me" to a contact after you rotate a proxy without linking the two —
   which would defeat the point. Long-lived relationships keep their proxy; you rotate the
   one-time / suspect ones, and re-establish out of band when you rotate a kept one.
6. **The admission capability is per-proxy — FIXED (A8-4, #206).** Credentials live in one
   `capabilities.dat` on the account's root path, but the key inside names both halves:
   `<relay-id>:<slot>`, where slot is `root` or `p<index>`. Every channel presents the credential
   IT earned, so a relay watching the wire sees N unrelated `capability_id`s where it used to see
   one account, and one channel's traffic no longer burns another's rate budget.

   **What was wrong before.** An earlier revision of this document argued that splitting the
   capability "buys no real anonymity gain", because a relay serving several proxies over one
   connection can cluster them from timing anyway. That argument had its premise backwards.
   `Peer::scope_for(handle)` derives a SOCKS stream-isolation token PER HANDLE, and handles are
   per-purpose, per-box, per-epoch — so over Tor each request already rides its own circuit and
   the connection does NOT link two proxies. The connection-level clustering the dismissal leaned
   on is exactly what per-handle isolation had already removed, which left the shared
   `capability_id`, sent in the clear on every deposit, as the ONLY linkage channel in the
   configuration proxies exist to serve. Direct-connection users were linked by IP regardless;
   Tor users were linked by this and nothing else.

   **How issuance works now.** `client::earn_missing_capabilities` walks (live proxy × relay) and
   earns wherever a channel has none of its OWN — a `Store::has_own_capability_for` check, so the
   pass fills gaps and never re-earns. It runs at unlock, when a relay is configured, and when a
   channel is minted (before the announce: a channel with no credential is skipped by
   `publish_all`, since creating a bundle slot is metered). `Store::burn_proxy` removes that
   channel's credentials in the same cascade that removes its session state — they are keyed per
   slot inside one file, so nothing else would ever reach them.

   **The price, paid rather than hidden.** A Public relay's door is proof-of-work, so N channels
   means solving it N times; and because quota is metered per `capability_id`, one account's total
   addressable throughput at that relay grows N-fold. The second is a real weakening of an
   anti-abuse control, accepted deliberately: a per-account bound cannot exist without a
   per-account identifier, which is the thing being removed.

   **Offline is a first-class outcome, not an error.** Earning needs a round trip, so a channel
   created without a network has no credential and will SKIP that relay when sending. Every such
   gap is reported (`CapabilityBackfill::still_missing`) rather than swallowed, and the next
   online pass fills it.

   The unlock-time pass runs OFF the unlock path, on its own thread, and re-announces if it earned
   anything. A public relay's difficulty is capped at 26 bits (SEC-41), so filling several
   channels' gaps at once is seconds of hashing — inline, that is a UI that will not open while it
   grinds. The passes the user explicitly triggers (configuring a relay, adding a backup, minting
   a channel) stay inline, because there the user is waiting on the result and a channel that
   cannot reach the relay when the call returns just looks broken.

   **The remaining honest limit: invite-only relays.** An operator invite is ONE credential,
   resolved once and revocable as a unit (#231) — N channels cannot each hold their own unless the
   operator mints N invites. `Store::save_shared_capability_for` stores such a credential for every
   channel, and it is a separate method precisely so that sharing is something a caller ASKS for
   and never what happens when per-channel issuance fails. At an invite-only relay, therefore, this
   account's channels do still present one `capability_id` and that relay can cluster them. The
   public/PoW door has no such limit. (The dev capability is shared too, for the opposite reason:
   its secret is published in this repository, so it is the same id for every user of this build.)

## Relationship to what is already shipped

- **Discovery / contact codes / one-time invites** (PR e232ccf) are re-targeted onto **proxies**:
  a code resolves to a proxy IK, never to anything permanent. This is what makes them meaningful —
  a burned code and a burned proxy cost you nothing.
- **Channels** (PR 67f0a99/9e6a444) — a public channel becomes a proxy configured to auto-accept;
  its posts are still root feed content, fanned out to subscribers through that proxy.
- **Publications** (PR e498216/4e4aeaa) fan out per-contact through each contact's proxy.
- The frozen root `derive` and existing single-identity accounts are **not** touched; the change
  is additive.

## Phased build

1. **Crypto core** — `seed::derive_proxy_from_secret(secret)` on its own domain (#207: no longer
   phrase-derived, no conformance vector to pin — see "Proxy derivation and destruction" above).
   Additive; nothing breaks.
2. **Data model** — the root store keeps a proxy registry (index + label + its own random
   `secret`), tags contacts / sessions with a `proxy_id`, and is marked "does not publish."
   Burning removes a registry entry outright, not a flag flip.
3. **Network** — each proxy publishes its own bundle / OPKs; poll every proxy's mailbox;
   discovery / invites / add-by-code target a chosen proxy; inbound binds to (contact, proxy).
4. **Unified inbox** — aggregate every proxy's chats into one list under the root; a chat opens as
   its proxy; replies go out from that proxy; the feed fans out per proxy.
5. **UX** — create / rotate / burn proxies; the "personal proxy for one contact" option (default
   is a reusable proxy per group); the honest wording above. Two-client tested before any
   announcement.
