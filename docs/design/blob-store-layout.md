# One file per blob, not one per chunk

Status: design accepted, not implemented. The layout change and the fsync batching are one
slice, because doing either alone throws away most of the other's benefit.

## What is wrong with the current layout

A blob's ciphertext lives in `<id>.c<index>` — a file per chunk. A 1 GB upload at 60 KiB a
chunk is about seventeen thousand files, in one directory, for one transfer. Every chunk
costs a create, a write, an fsync and a rename, and every recovery scan costs a directory
walk proportional to the number of chunks rather than the number of blobs.

The design was right for what it bought at the time: chunks may arrive out of order, and a
file per chunk makes that trivial and makes a torn write impossible to spread into a
neighbour. Both properties have to survive the change, which is what makes this more than a
rename.

## The layout

    <id>.data   ciphertext, appended in ARRIVAL order
    <id>.meta   header + per-chunk (index -> offset, length)

Arrival order, not index order. Out-of-order arrival was the reason for the old layout and
appending keeps it free: a chunk goes at the current end of `.data` whatever its index, and
the index in `.meta` is what makes it findable. Writing at `index * CHUNK` instead would
need a fixed chunk size, and the last chunk of every blob is short.

A re-sent chunk appends a second copy and the index points at the new one. The old bytes
become dead space in `.data`. That is deliberate: overwriting in place would put a torn
write on top of data the index still points at, and the space is bounded by how many
re-sends a transfer makes — which the resume watermark already keeps small.

## The ordering that keeps it crash-safe

    append chunk to .data
    fsync .data                 <- the bytes exist
    update .meta with (index -> offset, len)
    fsync .meta                 <- the bytes are findable

**Data before index, always.** The reverse order leaves an index entry pointing at bytes
that may not be there, and a reader following it gets whatever the file happened to contain
— which after a crash is the previous blob's ciphertext or nothing. Failing to find a chunk
is recoverable; finding the wrong one is not, because it decrypts to garbage under a key
that should have worked and looks like corruption of the sender's data.

A crash between the two leaves the bytes present and unindexed: dead space, and the chunk
re-sends. That is the direction the ordering chooses.

## Where the batching comes in, and why it is the same slice

Written per chunk, the sequence above is two fsyncs a chunk — worse than today's one. The
layout only pays once several chunks share them:

    append chunk A, B, C to .data
    fsync .data                 <- one, for all three
    update .meta with three entries
    fsync .meta                 <- one, for all three

Which is exactly the group commit already built for the mail log: append many, sync once,
and answer nobody until the sync returns. Hence one slice. Landing the layout alone would
double the fsync count and be a regression measured honestly.

## What must not be lost

**Out-of-order arrival.** Kept by construction — see the layout.

**A torn write cannot damage a neighbour.** In the old layout, separate files gave this for
free. Here it comes from appending: a torn append damages only the tail of `.data`, which no
index entry points at yet, because the entry is written after the fsync.

**The resume watermark.** `stat` returns how many chunks are contiguously present. That now
reads from the index rather than from a directory listing, which makes it O(received)
instead of O(files) — the same complexity the in-memory metadata already promised and the
filesystem was quietly undoing.

**Per-sender and global byte caps.** Unchanged: they count bytes, and the bytes are the
same. Dead space from re-sends is not counted against the sender, which is a small
generosity worth naming rather than discovering.

## What this does not fix

The number of blobs. A store with many small blobs still has two files each, and the
directory walk on recovery is proportional to that. This slice removes the chunk factor,
which is the one that scales with file size — not the blob factor, which scales with usage.
