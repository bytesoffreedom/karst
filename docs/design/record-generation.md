# A record has to say which generation it belongs to

Status: **open decision, blocking.** Found while building the container's object path (#325). The
code in the repository is correct today by a coincidence that will not survive the next slice, and
the obvious fix is arithmetically impossible. Written down so the choice is made deliberately.

## The problem

A payload and a map node are sealed with the **generation** in their AAD. The reader takes the
generation from the space's **current root**.

That is right only while every record is rewritten by every commit. It is true today — `write_object`
rewrites the whole map path each time — and it stops being true the moment copy-on-write leaves an
untouched node in place, which is the entire point of copy-on-write: without shared nodes, writing
one object orphans every other object that shares a node, and at this fan-out that is all of them.

When it stops being true, the untouched node does not open. Not "opens as the wrong thing" —
`record::open` returns `None`, deliberately, because a wrong key, a wrong place and a wrong
generation are one answer. The user is shown corruption.

## Why the obvious fix does not fit

Roots and capsules already solve this: eight bytes of generation in the clear ahead of the record,
covered by the AAD so editing them makes the record fail rather than redirect. For a payload or a
map node there is no room:

    block_payload                     65536
    RECORD_FRAMING                       42
    logical_data                      65494
    sealed payload   = 42 + 65494  =  65536   exactly fills the block
    with an 8-byte prefix          =  65544   8 bytes past the end
    sealed map node                =  65530
    with an 8-byte prefix          =  65538   2 bytes past the end

This was implemented before the arithmetic was checked. The overflow lands in the **next block's
first capsule copy**, so the tests failed in roughly two runs out of three with a different block
number each time — 62, 100, 10, 61, 52 — depending on whether the allocator happened to hand out
adjacent blocks. It read exactly like a race, and several rounds went into looking for one. The
arithmetic took half a minute once it was done instead.

## The options

**(a) Shrink the record's plaintext by eight bytes.** `logical_data` and `fanout` both fall, which
changes `format_params`, `format_hash`, possibly the tree depth, and every figure in
`container-measurements.md`. Pre-alpha makes the format break free; the re-measure is the real cost.

**(b) Take the generation from the block's capsule**, which already carries one in the clear.
**Does not work**: a `Public` session holds no ownership-layer key, so it could not read the capsule
and therefore could not read its own space.

**(c) Drop the generation from the record's AAD.** Then a record from generation N can be replayed
in place of one from generation M at the same position, which is the rollback the generation is
there to prevent.

**(d) Put the generation in the RECORD HEADER, where the version and the type already sit.**
`RECORD_FRAMING` goes 42 → 50 and `logical_data` falls by the same eight bytes as in (a) — so it
costs exactly what (a) costs — but it buys more:

- every record becomes self-describing, so no caller has to remember to add a prefix;
- roots and capsules can eventually drop their bespoke prefixes and use the same mechanism;
- `open` can read the generation out of the record instead of being handed one, which removes the
  class of bug rather than this instance of it — a caller cannot pass the wrong generation if it
  does not pass one at all.

**(d) is the recommendation.** It is the same price as (a) and it kills the class.

## What it touches

`record::{seal, open}`, `RECORD_FRAMING`, and through the geometry: `logical_data`, `fanout`,
possibly `depth`, `FormatParams`, `format_hash`, and the measurement tables. Every sealed record in
the format changes shape, so it is one slice with its own full run — not a patch on the end of
another one.
