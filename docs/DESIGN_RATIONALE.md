# Design rationale: why these algorithms

A record of the non-trivial choices in this codebase, and why each is a
reasonable fit for a single-user (or small-trusted-group), local-first
vault — rather than assumed or left implicit. Written once so a future
change has something concrete to argue with, instead of silence.

## Cryptographic primitives

| Purpose | Choice | Why |
|---|---|---|
| Password → key | Argon2id | The current recommended choice for password hashing/KDF (RFC 9106); resistant to both GPU and side-channel attacks better than PBKDF2/bcrypt. Parameters (~19 MiB, 2 passes) follow the RFC's interactive-use recommendation — tunable per vault via stored params, so raising them later doesn't break old vaults. |
| Content encryption | AES-256-GCM | Authenticated encryption (confidentiality + integrity in one primitive) with hardware acceleration (AES-NI) on essentially all target hardware, so per-block overhead stays negligible even at vault-wide scale. |
| Signatures | Ed25519 | Fast, small (64-byte) signatures, no parameter choices to get wrong (unlike ECDSA's nonce reuse footguns), and it's what a chain record can afford to carry per-record without bloating the format. |
| Key exchange | X25519 | Pairs naturally with Ed25519 (same curve family, well-audited implementations), constant-time by construction, no parameter choices. |
| Hashing | SHA-256 | Ubiquitous, fast, no known practical attacks at this length; used for chain linkage, file-content hashes, and (as a deliberately simplified KDF) key wrapping. |

All five are wired up via well-maintained crates (`argon2`, `aes-gcm`,
`ed25519-dalek`, `x25519-dalek`, `sha2`) — nothing here is hand-rolled
cryptography. The two spots that *are* simplifications are called out
explicitly where they live, not hidden: the DEK-wrapping KDF is a
single SHA-256 pass rather than a formal HKDF (`core::crypto`), and the
network handshake is a small from-scratch construction rather than
Noise/TLS (`net::handshake`). Both are documented as the first things
to harden if the threat model broadens past "small trusted group."

## Block allocation: bitmap + first-fit

A single bit per block, scanned linearly for the first free run. The
alternatives (a free-list, a buddy allocator, best-fit) all trade
allocator complexity for either faster allocation or less
fragmentation — neither matters much here:

- **Block counts are small enough that linear scan is fast in absolute
  terms.** A 10 GB vault at the default 4096-byte block size is
  ~2.5M blocks, i.e. ~320 KB of bitmap — scanning it is a memory-bound
  operation on data that's already resident (the bitmap is loaded once
  at open and kept in memory for the vault's session), not a
  bottleneck next to the disk I/O the same operation also needs.
- **First-fit doesn't need to be optimal** because file layout doesn't
  need to be contiguous or predictable: every file's block list is
  already indirected through direct pointers + an overflow chain, so
  fragmentation costs one extra pointer dereference per index-block
  boundary, not a performance cliff.
- A free-list would avoid the scan but costs a persistent structure of
  its own (another region to keep consistent, another thing that can
  corrupt) for a win that only shows up at capacities this design isn't
  targeting in the first place.

## File table and recipient keyring: fixed-size array + linear scan

Both are scanned linearly by name/identity on lookup, O(max_files) or
O(max_recipients). This is the one place worth being explicit about the
trade-off, since a hash index would be the "obvious" upgrade:

- `max_files` is capacity-scaled but capped at 4096; `max_recipients`
  is a flat 16 (a *trusted set of devices*, not a public directory —
  see the network architecture doc). A linear scan over either is
  sub-millisecond, several orders of magnitude below the disk I/O
  (block reads/writes) any operation using the result will also do.
- A hash index would mean either an on-disk hash table (real
  complexity: collision handling, resizing, a second corruption
  surface) or an in-memory-only index that has to be rebuilt from the
  linear data on every open anyway — at which point it's only saving
  time on repeated lookups *within* one session, which isn't where this
  format spends its time.
- The fixed-array design keeps the format's "every region is a simple,
  bounds-checked array of fixed-size records" invariant uniform across
  the header, file table, recipient keyring, *and* chain — one mental
  model, one validation routine shape, applied four times, rather than
  a bespoke structure per region.

If `max_files` ever needs to grow past a few thousand, that's the
signal to revisit this — not before.

## The hash chain: an admin-signed, bounded ring buffer

Three properties, each chosen deliberately:

- **Hash-linked** (each record embeds the previous record's hash) so
  any tampering with an old record breaks every record after it —
  standard tamper-evidence, same idea as a blockchain's chain without
  needing any of the consensus machinery that word usually implies.
- **Signed**, not just hashed, because the chain now also has to answer
  a second question beyond "has this been tampered with locally": "did
  this change really come from the vault's admin?" A hash alone can't
  answer that for a peer with no other channel to the admin; a
  signature over each record's hash can, using only the admin's public
  key the peer already has.
- **Bounded** (a fixed-size ring buffer, oldest records overwritten)
  rather than an ever-growing log, for the same reason the file table
  is fixed-size: a vault's metadata regions have to be sized at
  creation time to keep the single-file format's layout simple, and an
  unbounded chain would either need to be the *last* region (breaking
  the "data region is always last, contiguous" invariant once it grew)
  or need its own separate growth mechanism. The bound trades perfect
  audit history for a fixed, predictable format — acceptable since the
  chain's job is tamper-evidence and sync bookkeeping, not a permanent
  audit log. (The sync layer's `PatchJournal` inherits the same
  trade-off in miniature, on purpose, for the same reason: see
  `net::journal`.)

## Peer-to-peer sync: byte-range patches over semantic diffing

The sync protocol ships `(offset, bytes)` ranges — literally "here's
what changed on disk" — rather than higher-level operations like "file
X was updated with content Y" that a peer would have to re-derive
locally. This was the one place a simpler mechanism turned out to
subsume what looked at first like it needed real distributed-systems
logic:

- Because a peer's replica starts as a byte-identical copy of the
  admin's file (from the initial `join`), and every mutation already
  funnels through a small number of write call sites in `Vault`
  (`write_at`), recording exactly those ranges and replaying them
  verbatim on the peer reproduces the mutation with no
  operation-specific replay logic, no risk of the peer's replica
  drifting from a subtly different reimplementation of "apply an
  update," and no serialization format for file content beyond what
  the vault format already has.
- The cost is that a patch's size is tied to how much actually changed
  on disk, not how much changed conceptually — updating one byte inside
  a large file still ships that file's entire re-encrypted block, not
  a byte-level diff. Byte-level diffing within a block would need a
  binary-diff algorithm (e.g. rolling-hash/rsync-style) for a saving
  that only matters for large files edited in tiny increments; not
  implemented, and not worth the complexity until that pattern shows
  up in practice.

## Session/inactivity timing: injectable clock, not real sleep

`core::session::Session<C: Clock>` is generic over a `Clock` trait so
tests can advance a `ManualClock` deterministically instead of actually
sleeping 30 seconds per test run. This is standard practice, listed
here mainly so it's clear the pattern is intentional and should be
followed for any future timing-dependent logic (the patch journal's
bounded window and the chain's ring buffer are both *count*-bounded
rather than time-bounded for exactly this reason — a count is
trivially deterministic to test; wall-clock expiry isn't).
