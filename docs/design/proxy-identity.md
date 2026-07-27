# Proxy identity — a root with no address, reached only through disposable channels

**Status: DESIGN. Phase 1 (HD derivation) in progress; nothing here is shipped yet.**
This document is the authoritative description of the model so the code, the roadmap,
and the honesty in the UI stay aligned as it is built. Source of truth is the code; when
they disagree, fix this doc.

## The problem this fixes

Until now a KARST identity **is** its identity key (IK): the IK is your permanent address,
the thing you hand out, the thing a contact code resolves to, and the thing every session,
publication and channel is keyed on. That has a structural flaw the model below removes:

- **The IK cannot be changed.** It is derived (frozen) from your 12-word phrase — it *is* your
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

- its **HD index** and the **keypair** derived from the seed at that index (its IK is the
  address a contact uses to reach you),
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

## HD derivation (and its freeze discipline)

Proxies are deterministic children of the same phrase:

```text
proxy_n = HKDF-Expand(PRK, info = "KARST-proxy-derive-v1" ‖ le32(n))
```

on a **separate, independent HKDF domain** from the frozen root `derive` (`seed.rs`,
`"KARST-identity-derive-v1"`) — so proxies never collide with the (untouched) root contract, and
the root's frozen phrase→IK vector is unaffected. Consequences:

- **Unlimited disposable identities, all recoverable from the 12 words**, with no extra backup —
  "burning" a proxy is just ceasing to use an index.
- **This domain is ALSO frozen the moment the first real proxy exists** — changing the info string
  or the index encoding would orphan every proxy anyone has handed out. A conformance vector is
  pinned in the first commit, exactly like the root's `frozen_derivation_vector`.

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
3. **Recovery gives keys, not conversations.** The phrase re-derives your proxy *keys*
   deterministically — but **not** which indices are live, **not** the contact↔proxy mapping, and
   **not** ratchet state; those live only in the encrypted vault. So "recoverable, no extra
   backup" means *empty, re-derivable identities*, not your history. Say exactly that.
4. **Whoever you accept learns that proxy's IK** — it is unavoidable for E2E — but it is a
   disposable proxy IK, not your identity, and it is per-channel revocable.
5. **Continuity across rotation costs a re-handshake.** With no stable public identity there is no
   way to *prove* "it is still me" to a contact after you rotate a proxy without linking the two —
   which would defeat the point. Long-lived relationships keep their proxy; you rotate the
   one-time / suspect ones, and re-establish out of band when you rotate a kept one.

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

1. **Crypto core** — `seed::derive_proxy(entropy, index)` on its own frozen domain + a pinned
   conformance vector. Additive; nothing breaks.
2. **Data model** — the root store keeps a proxy registry (indices + labels + active), tags
   contacts / sessions with a `proxy_id`, and is marked "does not publish."
3. **Network** — each proxy publishes its own bundle / OPKs; poll every proxy's mailbox;
   discovery / invites / add-by-code target a chosen proxy; inbound binds to (contact, proxy).
4. **Unified inbox** — aggregate every proxy's chats into one list under the root; a chat opens as
   its proxy; replies go out from that proxy; the feed fans out per proxy.
5. **UX** — create / rotate / burn proxies; the "personal proxy for one contact" option (default
   is a reusable proxy per group); the honest wording above. Two-client tested before any
   announcement.
