# Compressing before the padding: what it is actually worth

Status: **measured, and the measurement does not support building it yet.** The task this comes
from (#275) was written with a benefit in mind that depends on a mechanism the tree does not have.
This note records the numbers so the slice is either sized honestly or left alone, rather than
re-argued from the same estimate a third time.

## The safety argument is sound, and it is not the question

Compressing before encrypting is normally forbidden, because the ciphertext length then varies with
the plaintext's content — CRIME and BREACH. That condition is genuinely lifted here: since PRIV-1
every ratchet plaintext is padded to a fixed `PADDED_LEN` before it is sealed, so the output size is
constant by construction and there is no length channel to leak into.

So "is it safe" is not what stops this. "Does it buy anything" is.

## What one padded block is

    MAX_PACKET_SIZE   3840      the stage-0 admission ceiling
    - framing          208      admit framing + opener framing + AEAD tag
    - sealed KA       1235
    - ML-KEM ct       1088
    = PADDED_LEN      1309
      MAX_PAYLOAD     1305      what a caller may hand to `pad`

One `Content` value becomes one `pad()` call becomes one block becomes one ratchet position. **That
chain is what decides the wire cost, and compression does not shorten it.** A 40-byte reaction and a
1300-byte paragraph already cost exactly the same.

## The measurement

Deflate at a pinned level, over real payloads. `chunks` is at `MAX_CHUNK_PAYLOAD` (1024) and `slots`
is after padding up the bundle ladder `[1, 4, 16]` — the two counts that actually cost something.

| payload | bytes | deflate | chunks | slots |
|---|---|---|---|---|
| chat message, 1 KB | 1 024 | 154 (15%) | 1 → 1 | **1 → 1** |
| text file (this repo's `bundling.md`) | 11 786 | 4 997 (42%) | 12 → 5 | **16 → 16** |
| PNG, 56 KB, QR-like (highly redundant) | 56 389 | 44 139 (78%) | 56 → 44 | **64 → 48** |
| PNG, 1.7 MB, photographic | 1 744 572 | 1 745 064 (**100.03%**) | 1704 → 1705 | **1712 → 1712** |
| random bytes | 200 000 | 200 071 (100.04%) | 196 → 196 | **no change** |

And on realistic *single* messages — varied natural prose, no trained dictionary:

| sample | raw | deflate | ratio |
|---|---|---|---|
| short RU (one sentence) | 125 | 96 | 77% |
| short EN (one sentence) | 77 | 75 | 97% |
| medium RU (~600 B) | 637 | 339 | 53% |
| medium EN (~400 B) | 364 | 228 | 63% |
| mixed text with URLs | 298 | 219 | 74% |

Short inputs are where deflate is weakest: there is almost no history to learn from. The "chat text
compresses 2–3x" figure in the task holds only for long or repetitive text, and the one sample that
reached 15% was a repeated sentence — an artefact of the test, not of chat.

**A trained dictionary would fix exactly that, and it is refused.** A dictionary built from our own
traffic turns compression ratio into a content oracle: how well a message compresses against a known
corpus is a measurement of how much it resembles that corpus.

## What the numbers say

1. **Nothing for a chat message.** Fixed block in, fixed block out. This is the common case and the
   gain is exactly zero.
2. **Nothing for photographic media**, which is what the in-band bulk transfers (avatar, gallery,
   post image) actually carry. Deflate *grows* an already-compressed image, so it needs a
   store-uncompressed fallback just to break even.
3. **Something for compressible bulk, sometimes.** The QR-like PNG dropped 64 slots to 48. The text
   file halved its chunks and changed nothing, because 12 and 5 both round to the same rung — the
   ladder swallows the saving. So the bulk gain is real but lumpy, and it depends on a rung boundary
   rather than on the compression.

## The benefit that is real, and its cost

`content::MAX_TEXT_BYTES` is 1024 against a `MAX_PAYLOAD` of 1305 — only 281 bytes of headroom, so
it cannot be raised much as things stand. Compressed, 8 KB of ordinary prose fits in one block, and
a much larger limit becomes possible.

The cost is that **the limit stops being a number.** Whether a message fits would depend on how well
it compresses, so 3 000 characters of prose would send and 3 000 characters of dense or already-
compressed content would be refused. That is a user-visible consequence the task does not mention,
and it is the kind of thing that should be decided deliberately rather than discovered by a user
whose message will not send.

## What this was really pointing at

The task's own figure — "not ~23 logical elements per block but 50–70" — describes **packing several
`Content` items into one padded block.** That mechanism does not exist: today it is strictly one
item per block. Packing is where the large win is, because it would turn a four-message bundle into
one envelope and one ratchet position, which also relieves the `MAX_SKIP` pressure that
`bundling.md` names as padding's real cost. Compression would then multiply that win instead of
being wasted against a fixed floor.

Packing is not a free follow-up: one ratchet position carrying N messages changes partial delivery,
per-message acknowledgement and the loss ledger all at once. It is a design slice with a threat
argument of its own, not a knob.

## The order this should be done in

1. **Packing** — several `Content` items per padded block, with the delivery-semantics questions
   answered explicitly.
2. **Compression** — on top of packing, where it multiplies a real saving, with a one-byte
   compressed/stored flag inside the block, a deterministic pinned encoder shared by every client
   (differing levels would give differing sizes before padding, which is a weak implementation
   fingerprint), no trained dictionary, and a store-uncompressed fallback for incompressible input.

Doing 2 before 1 buys the numbers in the table above: nothing for chat, nothing for photos, and an
occasional rung on compressible bulk.
