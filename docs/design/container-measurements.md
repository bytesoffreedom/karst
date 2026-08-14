# The container's numbers, measured

Status: measured (#318). The plan lists these as open engineering quantities and says the format's
constants should not be frozen until they exist. They exist now — the file backend is what made
them measurable, because until it landed every layer ran over a `Vec` and there was nothing to
measure against.

Reproduce with `cargo test -p vault --test measurements -- --nocapture`, and **with `--release`
for the KDF figure** — see the last section for why that is not a detail.

## The block-size trade, which is the decision everything else waits on

Two capsule copies cost `2 × CAPSULE_ALIGN` = 8192 bytes per block, whatever the block holds. That
is a fixed tax, so the overhead is decided entirely by the block size — and the same choice sets
how much gets rewritten for a small change, because a copy-on-write block is rewritten whole.

| block payload | stride | two-copy overhead | blocks per GiB | blocks per 1-byte edit | bytes moved |
|---|---|---|---|---|---|
| 4 KiB | 12 288 | **66.7%** | 87 381 | 5 | 60 KiB |
| 16 KiB | 24 576 | 33.3% | 43 690 | 4 | 96 KiB |
| **64 KiB (shipped)** | 73 728 | **11.1%** | 14 563 | 4 | **288 KiB** |
| 256 KiB | 270 336 | 3.0% | 3 971 | 4 | 1.03 MiB |
| 1 MiB | 1 056 768 | 0.8% | 1 016 | 3 | 3.02 MiB |

Two things fall out of the table that were not obvious from the design:

**Small blocks are not available.** At 4 KiB the container spends two thirds of itself on capsules.
That is not a tuning question, it is the page-separation rule pricing itself: the two copies must
sit in different pages, so the minimum a block can cost is two pages plus its payload. A format
that wanted 4 KiB blocks would have to give up the separation, and the separation is what makes a
single torn write survivable.

**The shipped 64 KiB is a middle, not a measurement.** It buys 11.1% overhead for 288 KiB moved per
one-byte edit. Whether that is the right point depends on the access pattern of whatever sits on
top, and the messenger's pattern is not yet known — it currently stores a whole snapshot per save,
where amplification barely matters and overhead is the whole cost. **If that stays true after the
wiring, 256 KiB is the better choice** (3.0% overhead, and the edit cost is irrelevant when every
save rewrites everything anyway). The number should be revisited with the wiring's real pattern in
hand rather than now, from a guess about it.

## Commit shape

| blocks in the transaction | writes | barriers | writes per barrier |
|---|---|---|---|
| 1 | 8 | 8 | 1.0 |
| 2 | 11 | 8 | 1.4 |
| 8 | 29 | 8 | 3.6 |
| 32 | 101 | 8 | 12.6 |

**Eight barriers, always.** The commit has eight ordered stages whether it touches one block or
fifty, so the fsync cost of a transaction is constant and the per-block cost amortises against it.
This is the argument for batching writes into one transaction rather than committing per block: at
32 blocks a barrier covers 12.6 writes instead of 1.

Three physical writes per logical block — reserved capsule, payload, live capsule. The map path is
what turns one logical change into four blocks at the shipped geometry (depth 3 plus the data
block).

## Map fan-out

| block payload | fan-out | depth |
|---|---|---|
| 4 KiB | 505 | 4 |
| 64 KiB | 8 185 | 3 |
| 1 MiB | 131 065 | 2 |

Fan-out fell by one per level when `RECORD_FRAMING` went 42 → 50: the generation moved into the
record header so that a record can say which generation it belongs to (`record-generation.md`).
Depth is unchanged, so nothing else in this note moves — the block-size trade, the commit shape and
the header cost are all as measured.

Depth is computed over the LOGICAL address space, not over the container's size, so it does not
change when a container does — which is the property that keeps a transaction's worst case
computable in advance.

## Header

2458 bytes, fixed. 0.0037% of a 64 MiB container, 0.000014% of a 16 GiB one. It must not grow with
the container: a header whose size tracked the file would be saying something about the file.

## The KDF, and why the build matters

Parameters: Argon2id, m_cost 128 MiB, t_cost 3, p_cost 1.

| build | one attempt | guesses/sec/core | 2^40 keyspace |
|---|---|---|---|
| release | **189 ms** | 5.3 | 6 584 core-years |
| debug | 3.15 s | 0.32 | 109 871 core-years |

**The debug figure overstates the attacker's cost by 16.7×**, and it is the one a developer gets by
default. Quoting it would be claiming a defence the shipped binary does not have, so the
measurement prints which profile it ran under and refuses to be quoted from a debug build.

189 ms per guess on one core is the number a parameter choice has to be argued from. It is a
deliberate cost on the honest user's unlock too — one that is paid once per unlock, against an
attacker who pays it per guess.

## What is still not measured

- **Recovery time after a crash, and allocator behaviour at high fill.** Both need a container that
  is actually full of data, which needs the wiring.
- **The cost of the lazy hash check on the hot path.** Same reason: there is no hot path until
  something reads through it.
- **Credit upper bound versus actual spend per object-API operation.** The planner is tested for
  never exceeding its estimate; what the estimate costs in practice needs real operations.

All three are blocked on the same thing — an account living in the container — and are listed here
rather than guessed at.
