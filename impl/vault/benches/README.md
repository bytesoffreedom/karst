# What can be measured today, and what cannot

The plan lists numbers to be established by measurement rather than chosen. Most of them
cannot be measured yet, and saying so is the point of this note — a benchmark run against
an in-memory harness would produce figures that look like measurements of the format and
are measurements of a `Vec<u8>`.

## Measurable now (pure CPU, no storage involved)

- **Argon2id at the pinned profile.** The unlock latency a person actually waits through,
  and the cost per guess an offline attacker pays. Depends on nothing but the CPU.
- **Record seal and open throughput.** XChaCha20-Poly1305 plus the aad construction, per
  record. Sets the ceiling on how fast the container can go once storage is not the
  bottleneck.
- **Capsule verification cost.** Whether the lazy hash check is cheap enough to run on a
  candidate, or must stay deferred to the moment a block is actually taken.
- **Allocator construction.** Fisher-Yates over the block count, once per mount, which is
  a fixed cost paid at unlock.

## Blocked on a real backing store

Every one of these is a property of storage, and `vault` has no I/O — `FaultyStore` is a
`Vec<u8>` and nothing here opens a file. Numbers from the current harness would be
meaningless in a way that is easy to miss once they are written down as constants:

- **Block payload size.** The right value trades write amplification against per-block
  overhead, and both sides of that trade are device behaviour.
- **Write amplification** — physical writes per logical write.
- **Barriers per operation.** The commit order fixes how MANY there are; what one costs is
  the filesystem's and the device's answer.
- **Recovery time** on a full container, which is dominated by reading capsules.
- **Allocator behaviour at high occupancy** — how many candidates get rejected before one
  is free, which depends on real fragmentation rather than a synthetic pattern.
- **Transaction reserve** at near-full, for the same reason.

## The rule

Until the blocked list has a backing store to run against, the constants it feeds stay
marked as placeholders in `geometry` and `params`. A placeholder that has been benchmarked
against the wrong thing is worse than one that is honestly unmeasured, because nobody
re-examines a number that looks settled.
