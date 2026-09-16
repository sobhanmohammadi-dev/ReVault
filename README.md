# Revault

A secure, single-file local vault with optional peer-to-peer sharing.

Revault stores everything — file data, metadata, encryption keyring, and
a tamper-evident integrity log — inside one `.rvlt` file. No sidecar
index, no external database, no required companion files. That single
file is enough to reopen and fully operate the vault on its own.

Beyond local storage, a vault's admin (whoever created it) can grant
other people's devices decrypt access and sync changes to them directly,
device to device — no central server ever holds vault data or decides
who can sync.

> **Status.** This is an actively-developed project, built and verified
> incrementally across many sessions (93 automated tests, all passing).
> It has not had independent security review. The cryptography uses
> well-established primitives throughout, but the network handshake in
> particular is a deliberately simple, from-scratch construction — see
> [Security model](#security-model) below before relying on it for
> anything sensitive.

## Contents

- [Features](#features)
- [Getting started](#getting-started)
- [Using the TUI](#using-the-tui)
- [Using the CLI](#using-the-cli)
- [How sharing works](#how-sharing-works)
- [The `.rvlt` file format](#the-rvlt-file-format)
- [Security model](#security-model)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Known limitations](#known-limitations)

## Features

- **Single-file vaults.** Create a vault with a name, description, and
  reserved capacity; everything lives in one `.rvlt` file.
- **Block-based storage.** Files are split into fixed-size blocks with a
  free/occupied bitmap allocator, so adding, updating, or deleting one
  file never requires rewriting the whole container.
- **Envelope encryption.** The vault's actual content key (a random
  256-bit DEK) is independent of the admin's password — it's wrapped
  once for the password and once per granted peer identity. This is
  what makes sharing possible without ever exposing the password.
- **Tamper-evident, admin-signed integrity chain.** Every mutation
  (file added/updated/deleted, access granted/revoked) is recorded in a
  hash-linked chain, and every record is signed by the admin's Ed25519
  identity — so a peer can verify a change genuinely came from the
  admin without trusting the network it arrived over.
- **Strict access revocation.** Revoking a peer rotates the vault's
  encryption key and re-encrypts its contents in place, so a revoked
  peer's existing local copy becomes unreadable too — not just cut off
  from future updates.
- **Peer-to-peer sync**, no server: invite codes (hex-encoded identity +
  optional address), a lightweight authenticated+encrypted channel, and
  a sync protocol that ships either a full copy (first join) or a small
  incremental patch (reconnecting after missing only a few changes).
- **30-second inactivity auto-lock** in the TUI.
- Both a **TUI** (interactive terminal app) and a **CLI** (scriptable
  commands, including an interactive `serve` console) expose every
  feature.

## Getting started

Requires a recent stable Rust toolchain (edition 2024).

```sh
cd Ruvault
cargo build
cargo test    # 93 tests
cargo run -- start   # launches the TUI
```

## Using the TUI

`cargo run -- start` (or the built binary with no arguments other than
`start`) opens the interactive app. Four tabs, cleanly separated by
responsibility: **Vaults** (vault/file management only), **Network**
(connections, peer-to-peer, sharing — everything that touches the
network), **Logs**, **Settings**.

### Vaults tab

Browsing the vault list:

| Key | Action |
|---|---|
| `+` | Create a new vault (name, description, capacity like `10 GB`, password) |
| `↑`/`↓` | Move selection |
| `↵` | Unlock the selected vault (prompts for password) |

Inside an unlocked vault:

| Key | Action |
|---|---|
| `a` | Add a file (prompts for a source path on disk and a name to store it under) |
| `d` | Delete the selected file |
| `v` | Verify the vault's integrity (chain linkage, signatures, file hashes) |
| `q` / `Esc` | Lock the vault and return to the list |

The vault auto-locks after 30 seconds of inactivity regardless. Nothing
here talks to the network — that's all under the Network tab, which
operates on whichever vault you currently have unlocked.

### Network tab

Always available, regardless of whether a vault is unlocked:

| Key | Action |
|---|---|
| `j` | Join a vault as a granted peer, via an invite code (creates a new local replica, which then shows up in the Vaults tab) |

Once a vault is unlocked (from the Vaults tab), this tab also shows its
peer list and serving status, and adds:

| Key | Action |
|---|---|
| `g` | Grant the unlocked vault's access to a peer, via their invite code |
| `r` | Revoke the selected peer's access (asks for the vault password again — see [Security model](#security-model)) |
| `n` | Start/stop serving the unlocked vault to its granted peers |

Switching to the Vaults tab to lock that vault also stops serving it
(the serving session's lifecycle is tied to the vault being open, even
though its controls live here).

### Settings tab

Press `↵` to edit the vaults directory (where the app looks for `.rvlt`
files by default), `↵` again to save, `Esc` to cancel.

### Logs tab

Shows the app's own operational log (vault created/unlocked/locked,
files added/deleted, peers granted/revoked/synced) — separate from a
vault's internal, cryptographic integrity chain.

## Using the CLI

Alongside `start` (the TUI), five subcommands cover the network feature
end to end without the TUI:

```sh
# Print this device's identity/invite code. Include --listen if you're
# about to run `serve`, so the invite carries an address peers can dial.
cargo run -- whoami --listen 0.0.0.0:4433

# Grant a peer (their invite code) decrypt access to a vault.
cargo run -- grant my-vault.rvlt --password <pw> --peer <their-invite-code>

# Revoke access -- rotates the encryption key and re-encrypts the vault.
cargo run -- revoke my-vault.rvlt --password <pw> --peer <their-invite-code>

# Serve a vault to granted peers. This is an interactive session: it
# accepts peer connections *and* reads admin commands from stdin at the
# same time (type `help` once it's running).
cargo run -- serve my-vault.rvlt --password <pw> --listen 0.0.0.0:4433

# Join a vault as a granted peer, using an invite code that includes an
# address (from `serve`/`whoami --listen`).
cargo run -- join <invite-code> replica.rvlt
```

**Only one process should hold a given `.rvlt` file open at a time.**
Each open `Vault` handle caches its own copy of the header and block
allocator in memory; two independent processes writing to the same file
concurrently (e.g. `grant` while `serve` is also running against it)
could corrupt it. Use `serve`'s own `add`/`update`/`delete`/`list`
commands instead of a separate CLI invocation while a serve session is
running. There's no file lock enforcing this yet.

## How sharing works

Two trust layers, kept deliberately separate:

1. **Password → content key**, entirely local. Unchanged from a
   password-only vault, except the password now unwraps a random data
   key (the DEK) rather than being the key itself.
2. **Admin identity → write authority**, for the network. A long-lived
   Ed25519 keypair (generated once per device, stored outside any vault)
   signs every change that gets shared. A peer only ever needs the
   admin's *public* key — recorded in the vault's header at creation —
   to verify that a change really came from the admin. The password
   itself never crosses the network.

Granting a peer access wraps the vault's DEK for their X25519 public
key — an extra ~90-byte entry in the vault's bounded recipient keyring,
touching nothing else. Revoking is the one expensive operation by
necessity: a new DEK, the whole vault re-encrypted under it, and the
new key rewrapped for everyone who's left.

Syncing reuses the vault's own hash chain as the sync log: peers
compare `(next_seq, last_hash)` — a git-ref-style comparison — and the
admin sends either a full copy (first join, or if a bounded in-memory
patch journal doesn't cover how far behind the peer is) or just the
missing signed records plus the actual changed bytes.

Full design, including what's *not* implemented (peer discovery, a
formally-analyzed handshake) and why, is in
[`docs/ARCHITECTURE_NETWORK.md`](docs/ARCHITECTURE_NETWORK.md).

## The `.rvlt` file format

Version 2, little-endian throughout, laid out as:

```
[0, 1024)                          Header (fixed size, versioned, checksummed)
[bitmap_offset, +bitmap_len)       Block allocation bitmap (1 bit/block)
[file_table_offset, +len)          Fixed array of FileEntry slots
[recipient_offset, +len)           Fixed array of RecipientSlot slots (envelope-encryption keyring)
[chain_offset, +len)               Fixed array of ChainRecord slots (admin-signed, tamper-evident)
[data_offset, +block_count*4096)   Data block region
```

Every region is bounds-checked on read (offsets, lengths, counts all
validated before use), and every fixed-size record — header, file
entry, recipient slot, chain record — carries its own checksum. See the
doc comments at the top of `src/core/format.rs` for the exact byte
layout of each.

Files are split across 4096-byte physical blocks (encrypted
individually, block-by-block) referenced by direct pointers for the
first 8 blocks and a linked chain of overflow index blocks beyond that,
so a small edit to one file only touches that file's own blocks plus
its one file-table slot — never a full-container rewrite.

## Security model

What this *is*:

- AES-256-GCM for all content encryption, Argon2id for password-based
  key derivation, Ed25519 for signatures, X25519 for key exchange —
  all via well-maintained, widely used crates (`aes-gcm`, `argon2`,
  `ed25519-dalek`, `x25519-dalek`), not custom cryptography.
- Every block is individually authenticated (AEAD) with a nonce derived
  from `(file_id, physical_block_index)`, unique for the life of a key.
- The admin's password is required to unlock locally, and is *never*
  transmitted or derivable from anything sent over the network.
- Revocation is cryptographically enforced (key rotation +
  re-encryption), not just an access-list check.

What this **is not**, stated plainly rather than glossed over:

- **The network handshake is not a formally analyzed protocol.**
  `src/net/handshake.rs` implements a small, from-scratch authenticated
  key exchange (X25519 + Ed25519 + AES-256-GCM) — reasonable for a
  small trusted set of devices where you've already exchanged invite
  codes out of band, but it has not had the scrutiny that Noise or TLS
  have. MITM resistance comes from the caller checking the peer's
  identity against an invite code obtained out of band, not from the
  handshake alone. Swapping in a real Noise implementation (e.g. the
  `snow` crate) is the documented next step before trusting this on an
  adversarial network.
- **Key-wrapping uses a single-step SHA-256 KDF**, not a formal HKDF —
  a documented simplification (see `src/core/crypto.rs`), fine for this
  threat model, worth hardening if the audience broadens.
- **No file-locking** against concurrent processes on the same vault
  file (see the CLI section above).
- **This has not had independent security review.**

## Project layout

```
src/
  core/       The vault engine: binary format, crypto, block allocator,
              identity, session timeout, and the high-level Vault API.
              No UI or networking dependencies -- usable standalone.
  net/        Peer-to-peer networking: wire protocol, the
              authenticated channel, invite codes, sync orchestration,
              and the patch journal.
  tui/        The interactive terminal app (ratatui), including the
              background network bridge that lets a vault serve peers
              while the UI stays responsive.
  cli/        Command-line entry points (`start`, `whoami`, `grant`,
              `revoke`, `serve`, `join`).
docs/
  ARCHITECTURE_NETWORK.md   Full design doc for the sharing feature.
```

## Testing

```sh
cargo test
```

93 tests across every layer: on-disk format round-trips and corruption
detection, crypto primitives (including wrap/unwrap and tamper
rejection), the block allocator, full vault workflows (create, add,
update, delete, capacity enforcement, integrity verification), the
network layer (a real handshake over a loopback TCP socket, a full
join-and-read integration test, journal coverage logic, wire-format
round-trips), and TUI-adjacent logic (capacity parsing, slugification,
settings persistence).

## Known limitations

Tracked honestly rather than left implicit:

- **Peer discovery** (DHT/gossip) doesn't exist — v1 is manual invite
  codes with an embedded `ip:port` only.
- **The sync patch journal is in-memory only**, scoped to one serving
  session — reconnecting after the admin restarts `serve` (or the
  Network tab's serving session ends) always falls back to a full
  resync. Always correct, just not maximally efficient.
- **Joining from the TUI blocks the UI** for the duration of the
  connection (a one-off async runtime run synchronously). Fine on a
  LAN; a background version would follow the same pattern serving
  already uses.
- File table and recipient keyring are **fixed-capacity** (scaled from
  a vault's capacity at creation, not infinitely growable).
- Format version 1 (an earlier password-direct scheme, before envelope
  encryption existed) is no longer readable — there was no real
  deployed vault data at that point, so this was a clean breaking bump.
