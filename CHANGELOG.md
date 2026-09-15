# Changelog

Entries group related work; this isn't strictly per-commit. See `git
log` for the full, granular history.

## Vault storage engine

- Versioned binary `.rvlt` format: header, block allocation bitmap,
  file table, tamper-evident hash chain, data region — all
  bounds-checked and checksummed on read.
- Block-based storage: files split into 4096-byte encrypted blocks,
  direct pointers for the first 8 blocks and an overflow index-block
  chain beyond that, so edits never require a full-container rewrite.
- Password-based unlock via Argon2id, AES-256-GCM content encryption.
- Core vault operations: create, open, add/read/update/delete file,
  list files, integrity verification.
- 30-second inactivity session timer (clock-injectable for testing).

## TUI and CLI

- Interactive terminal app (ratatui): Vaults / Network / Logs /
  Settings tabs, vault creation and unlock forms, file browsing,
  add/delete/verify from inside an unlocked vault.
- Application-level settings persistence and operational log, separate
  from a vault's internal integrity chain.
- `start` CLI subcommand launching the TUI.

## Envelope encryption and peer identity (format v2)

- Breaking format bump: the vault's content key (DEK) became
  independent of the password, wrapped once for the admin's password
  and once per granted peer identity (a bounded recipient keyring).
- `Identity`/`PeerId`: per-device Ed25519 (signing) + X25519
  (encryption) keypairs, persisted outside any vault.
- Chain records gained an Ed25519 signature from the admin, and
  `verify_integrity` now checks it alongside hash linkage.
- `grant_access` / `revoke_access`, with revocation implemented as a
  strict key rotation + full re-encryption (not just an access-list
  removal) — so a revoked peer's existing local copy is also locked
  out, not just cut off from future updates.
- Admin-only mutation guard: every mutating method requires the vault
  to have been opened by an identity matching its recorded admin.
- Grant/revoke wired into the Vaults TUI (`p`).

## Peer-to-peer networking

- Wire protocol (length-prefixed framing, hand-rolled binary sync
  messages) and a lightweight authenticated+encrypted channel
  (X25519 + Ed25519 + AES-256-GCM — explicitly not a formally analyzed
  protocol like Noise, see `src/net/handshake.rs`).
- Hex-encoded invite codes (identity + optional address).
- Sync: full-copy join, and a byte-range change-log/patch mechanism
  (`Vault::take_change_log` / `apply_remote_patch`) so a peer's replica
  can be brought up to date by replaying exactly the ranges that
  changed, rather than resyncing operation-by-operation.
- A bounded in-memory patch journal so a peer reconnecting after
  missing only a few changes gets an incremental patch instead of a
  full resync.
- CLI: `whoami`, `grant`, `revoke`, `serve` (interactive — accepts
  peer connections and admin commands from stdin concurrently on one
  `Vault` handle), `join`.
- TUI: serve/stop from an unlocked vault (`n`) via a background-thread
  network bridge that never touches the `Vault` directly — it asks the
  main thread what to send, once per tick, so the file is still only
  ever mutated from the one thread that has it open. Join from the
  Vaults list (`j`).

## Fixes found during integration

- Windows build: `rand_core` 0.6's `OsRng` needed the `getrandom`
  feature enabled explicitly.
- `Vault` needed a hand-written (not derived) `Debug` impl for test
  assertions, without exposing the content key type's internals.
- A temporary-value-dropped-while-borrowed error in async test code
  (`tokio::join!` over an inline, unbound `Identity`).
- A real logic bug: block-count calculations for reading/deleting/
  updating a file used the raw physical block size instead of the
  usable-plaintext-per-block size the write path uses, breaking files
  large enough to need overflow blocks (>8 blocks). Caught by
  `cargo test`, not by review.
- A stale test offset left over from before the recipient keyring
  region was added, which had been landing outside the data region
  entirely; fixed to compute the real offset from the on-disk header.
