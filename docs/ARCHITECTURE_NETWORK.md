# Revault Network — Design Document (v1)

Status: **design + foundational crypto/identity implemented.** Transport
(actual peer-to-peer wire protocol) is the next phase and is *not* built
yet. This document is the reference for both.

## Goals, restated from the requirements discussion

- No central/base server ever holds vault data or controls who can sync.
  A small, lightweight bootstrap step (pasting in `ip:port` / an invite
  code) is fine for v1; pure P2P discovery (gossip/DHT) is a later
  enhancement, not a requirement for correctness.
- The person who creates a vault is its **admin**. Only the admin can
  author changes; peers can only receive and apply admin-signed changes.
- The admin can **grant** other trusted identities the ability to decrypt
  the vault (not just hold opaque encrypted bytes).
- The admin can **revoke** a peer. Revocation is *strict*: the vault's
  actual encryption key is rotated and the vault is re-encrypted, so a
  revoked peer's existing local copy becomes unreadable going forward,
  not just "stops receiving updates."
- Updates sent over the network should be incremental ("only send the
  part that changed"), not the whole `.rvlt` file every time.
- v1 admin identity is a single keypair on a single device. Multi-device
  admin (the same admin identity used from a phone and a laptop) is an
  explicitly deferred enhancement.

## Two separate trust layers

It's important these don't get conflated:

1. **Password → content key (existing, local).** Argon2id(password) is
   used to unlock the vault locally. This still exists, but it no longer
   *is* the content-encryption key directly (see envelope encryption
   below) — it's one way of unwrapping it.
2. **Admin identity → write authority (new, network).** A long-lived
   Ed25519 keypair identifies "the admin." Every mutating operation that
   gets propagated to peers is signed with this key. Peers verify the
   signature against the admin public key recorded in the vault's header
   at creation time and reject anything not signed by that key. The
   *password* never has to leave the admin's device and is never sent
   over the network — only signed, already-encrypted data is.

## Identity

Each participant (admin or peer) has a local **Identity**, generated
once and stored outside any vault (`~/.revault/identity`, alongside
`settings.cfg` — app-level, not vault-level, so it never violates the
single-file vault invariant):

- an **Ed25519** signing keypair — proves "this message really came from
  this person" (used for admin authorization and, on the peer side, for
  handshake authentication).
- an **X25519** encryption keypair — used only for *wrapping the vault's
  data key* for that identity (envelope encryption below). Kept separate
  from the signing key on purpose (mixing signing and encryption keys is
  a known footgun).

A person's shareable identifier (what you'd put in an invite / paste
into another device) is their **`PeerId`**: the two public keys plus a
short fingerprint, encoded as text. Implemented in `src/core/identity.rs`.

## Envelope encryption (replaces "key comes straight from the password")

Previously: `content_key = Argon2id(password)`, used directly for every
block. That only supports a single secret. To support "grant this other
identity decrypt access" without ever telling them the password, the
actual content key becomes independent of the password:

- **DEK** (Data Encryption Key): one random 256-bit key per vault,
  generated at creation. This is what actually encrypts every block, the
  same as `MasterKey` did before.
- The DEK is never stored in the clear. Instead, the vault's header
  keeps a small, bounded **recipient keyring** — a list of *wrapped DEK*
  entries, one per authorized identity:
  - **Admin's password slot**: `AES-256-GCM(key = Argon2id(password),
    plaintext = DEK)`. This is what `Vault::open(path, password)` uses,
    and it doubles as the password-correctness check (decrypt succeeds
    ⇒ password was right), replacing the old fixed-plaintext verifier.
  - **Peer slots**: for each granted identity, `X25519(ephemeral,
    peer_pubkey) → shared secret → HKDF → AES-256-GCM(DEK)`. A peer who
    has been granted access unwraps their slot with their own X25519
    private key; nobody else can.
- **Granting** access = adding one more wrapped-DEK slot. Cheap, doesn't
  touch vault content at all.
- **Revoking** access (per the "full/strict" decision): generate a brand
  new DEK, re-encrypt every block in the vault with it (this is
  necessarily a full-vault operation — there's no way to make old
  ciphertext unreadable without changing the key that reads it), rewrap
  the new DEK for every *remaining* authorized identity, and drop the
  revoked identity's slot entirely. This produces a new chain record
  (`KeyRotated`) and forces a full resync to every peer (the delta-sync
  optimization below doesn't apply to a rotation, by nature).

This is a breaking on-disk format change (recipient keyring region +
admin pubkey field in the header), so it bumps `FORMAT_VERSION` to `2`.
Format version 1 vaults (password-only, no network) remain readable —
the reader checks the version and treats a v1 vault as "networking not
available for this vault" rather than refusing it outright.

## The chain becomes the sync log

The existing tamper-evident hash chain (`ChainRecord`) already records
every mutation in order with a hash linking each record to the previous
one. For the network feature it gains one more field: an **Ed25519
signature by the admin key** over each record's hash. That single
addition turns the chain from "detects local tampering" into "peers can
verify these changes actually came from the admin," which is the core
of the whole trust model — a peer never has to trust *the network*, only
the admin's public key it already has.

## Sync protocol ("only send the part that's needed")

Peers exchange a tiny state summary first — `(chain_next_seq,
chain_last_hash)`, the same pair already stored in the vault header —
which is exactly a git-style ref comparison. If a peer's `seq` is behind
the admin's, the admin sends only the **missing chain records**, each
paired with the actual new/changed encrypted blocks that record refers
to (not the whole vault):

- `FileAdded` → the new file's blocks + its file-table entry.
- `FileUpdated` → the new blocks for that file (old ones are simply
  superseded; a peer applies them the same way `update_file` does
  locally) + the updated file-table entry.
- `FileDeleted` → just the tombstoned entry; no block data.
- `KeyRotated` → this one *is* a full resync by necessity (see above),
  clearly marked as such so peers don't expect it to be small.

Each patch is verified in order: signature checks out, `prev_hash`
matches the peer's current chain tip, block ciphertexts decrypt (if the
peer holds a DEK slot) or are just stored opaquely (if the peer is a
mirror-only replica in the future) before being applied. Anything that
doesn't verify is rejected and logged, never partially applied.

## Transport (next phase — not implemented yet)

Planned, in order of how much extra complexity each adds:

1. **v1 — manual peer list.** You paste in an invite string (encodes the
   peer's `PeerId` + address); the app dials out over plain TCP. `tokio`
   is already a dependency, so the async runtime is ready.
2. **Handshake.** Both sides prove identity (Ed25519 challenge) and
   derive a session key (X25519 ECDH). Rather than hand-rolling this,
   the plan is to use the `snow` crate (a maintained Noise Protocol
   Framework implementation) for the handshake instead of a bespoke
   scheme — this keeps us on "use established crates for crypto," the
   same rule the at-rest encryption already follows.
3. **v2 — gossip/DHT discovery**, so peers already known to each other
   can introduce new ones without any manual step, still with no server
   in the data or control path.

## What's implemented now vs. still deferred

Implemented: `Identity`/`PeerId`, the full envelope-encryption format
(v2 -- recipient keyring, DEK wrap/unwrap via X25519), `grant_access` /
`revoke_access` with full key rotation, admin-only mutation guards,
signed/verified chain records, `Vault::open_as_recipient`, a
byte-range change-log (`take_change_log`/`apply_remote_patch`/
`export_full`) that the sync protocol is built on, a lightweight
authenticated+encrypted channel (`net::handshake`, X25519 + Ed25519 +
AES-256-GCM -- explicitly *not* a formally analyzed protocol like Noise,
see that module's doc comment), the wire sync protocol
(`net::protocol`, `net::sync`: join / catch-up / live-push patch),
hex invite codes (`net::invite`), five CLI subcommands (`whoami`,
`grant`, `revoke`, `serve`, `join`), and grant/revoke wired into the
Vaults TUI (press `p` on an unlocked vault).

Still deferred:
- **Peer discovery** (DHT/gossip) -- v1 is manual invite codes with an
  embedded `ip:port` only.
- **A real Noise handshake** in place of the hand-rolled one.
- **Efficient catch-up sync** -- reconnecting after being offline always
  triggers a full resync rather than replaying missed patches, because
  there's no persistent, seq-indexed patch history kept anywhere yet
  (documented in `net::sync`). A bounded on-disk patch journal (mirroring
  the chain's own bounded-window design) would fix this.
- **Live push isn't wired into the TUI** -- `net::sync::push_patch` /
  `apply_incoming` exist and are tested, but nothing calls them from the
  running app yet (would need a background task + channel back into the
  synchronous TUI event loop, deliberately left out of this pass to
  avoid rushing that integration).
- **Connecting to a peer from the TUI** -- `serve`/`join` only exist as
  CLI commands right now.

Note: format version 1 (the original password-direct scheme) is no
longer readable -- `MIN_SUPPORTED_VERSION` is now 2. There was no real
deployed vault data at that point, so this was a clean breaking bump
rather than a migration.
