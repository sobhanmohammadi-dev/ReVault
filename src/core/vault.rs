//! High-level `Vault` API: the single entry point that ties the binary
//! format, block allocator, crypto, identity, and hash chain together
//! into create / open / add_file / read_file / update_file / delete_file
//! / grant_access / revoke_access / verify_integrity operations.
//!
//! # Envelope encryption and admin authority (format version 2)
//!
//! A vault's actual content key (the DEK) is independent of the admin's
//! password: it's wrapped once for the admin's password (`admin_key_slot`
//! in the header) and once per granted peer identity (a `RecipientSlot`
//! in the keyring region). `Vault::open` (password) and
//! `Vault::open_as_recipient` (peer identity) both end up with the same
//! usable content key, just unwrapped a different way.
//!
//! Only a `Vault` opened as the admin (i.e. via `open`/`create`, with a
//! local identity matching the header's recorded admin identity) can
//! call any mutating method -- `add_file`, `update_file`, `delete_file`,
//! `grant_access`, `revoke_access`. Every mutation appends a chain record
//! signed by the admin's identity, so a peer receiving that record over
//! the (future) network layer can verify it really came from the admin
//! without ever seeing the password.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::allocator::BlockAllocator;
use super::crypto::{self, Argon2Params, MasterKey};
use super::error::{Result, VaultError};
use super::format::{
    ChainOp, ChainRecord, FileEntry, Header, RecipientSlot, ADMIN_KEY_SLOT_LEN, CHAIN_RECORD_SIZE,
    ENTRY_FLAG_DELETED, ENTRY_FLAG_OCCUPIED, ENTRY_SIZE, HEADER_SIZE, MAX_FILENAME_LEN, MAX_RECIPIENTS,
    RECIPIENT_FLAG_OCCUPIED, RECIPIENT_SLOT_SIZE,
};
use super::identity::{Identity, PeerId};

/// Per-block on-disk framing overhead: a 4-byte plaintext-length prefix plus
/// the 16-byte AES-GCM authentication tag.
const BLOCK_FRAMING_OVERHEAD: u64 = 4 + 16;
/// Bytes reserved at the front of an overflow index block for `next` (u64)
/// and `count` (u32).
const INDEX_BLOCK_HEADER: usize = 12;

const ADMIN_KEY_SLOT_AAD: &[u8] = b"revault-admin-dek-v2";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Derives a stable u128 chain-log identifier for a peer from their
/// signing public key. Just a bookkeeping id for the chain, not a
/// security-relevant value.
fn peer_target_id(signing_pubkey: &[u8; 32]) -> u128 {
    let h = crypto::sha256(signing_pubkey);
    u128::from_le_bytes(h[..16].try_into().unwrap())
}

/// Summary of a file inside a vault, safe to display without exposing
/// plaintext contents.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Summary of vault-level metadata that can be inspected without unlocking
/// (name/description/capacity are not secret; contents are).
#[derive(Debug, Clone)]
pub struct VaultSummary {
    pub name: String,
    pub description: String,
    pub capacity_bytes: u64,
    pub created_at: i64,
}

/// A granted peer, as visible to the admin (no secret material).
#[derive(Debug, Clone)]
pub struct RecipientInfo {
    pub peer_id: PeerId,
    pub granted_at: i64,
}

pub struct Vault {
    file: File,
    header: Header,
    allocator: BlockAllocator,
    /// The vault's actual content-encryption key (the DEK), already
    /// unwrapped -- via the password (admin) or a recipient slot (peer).
    key: MasterKey,
    /// `Some` only when this Vault was opened/created by an identity that
    /// matches the header's recorded admin identity. Mutating methods
    /// require this.
    admin_identity: Option<Identity>,
    /// Every `(offset, bytes)` range written by a mutating call since the
    /// last [`Vault::take_change_log`]. This is the foundation of the
    /// network sync protocol: since a peer's local replica starts as a
    /// byte-identical copy of this file, shipping exactly the ranges that
    /// changed -- and replaying them verbatim -- reproduces the same
    /// mutation on the peer's copy without needing any operation-specific
    /// sync logic.
    change_log: Vec<(u64, Vec<u8>)>,
}

impl std::fmt::Debug for Vault {
    /// Hand-written rather than derived: `MasterKey` deliberately does
    /// not implement `Debug` (so the content key can never end up in a
    /// log/panic message by accident), so a derive here isn't possible
    /// without weakening that guarantee. This redacted view is enough
    /// for `Result::unwrap_err` in tests and any other debug printing.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("name", &self.header.name)
            .field("is_admin", &self.is_admin())
            .finish_non_exhaustive()
    }
}

impl Vault {
    // -----------------------------------------------------------------
    // Creation / opening
    // -----------------------------------------------------------------

    /// Reads only the header of a `.rvlt` file to obtain non-secret
    /// metadata, without requiring (or checking) the password.
    pub fn peek_summary<P: AsRef<Path>>(path: P) -> Result<VaultSummary> {
        let mut file = File::open(path)?;
        let mut buf = vec![0u8; HEADER_SIZE as usize];
        file.read_exact(&mut buf)?;
        let header = Header::decode(&buf)?;
        Ok(VaultSummary {
            name: header.name,
            description: header.description,
            capacity_bytes: header.capacity_bytes,
            created_at: header.created_at,
        })
    }

    pub fn create<P: AsRef<Path>>(
        path: P,
        name: &str,
        description: &str,
        capacity_bytes: u64,
        password: &str,
        admin_identity: Identity,
    ) -> Result<Vault> {
        if name.len() > super::format::MAX_NAME_LEN {
            return Err(VaultError::FieldTooLong);
        }
        if description.len() > super::format::MAX_DESC_LEN {
            return Err(VaultError::FieldTooLong);
        }

        let block_size = super::format::DEFAULT_BLOCK_SIZE;
        let block_count = capacity_bytes / block_size as u64;
        if block_count == 0 {
            return Err(VaultError::CapacityTooSmall);
        }

        // Scale the file table with capacity, within sane bounds; the
        // recipient keyring stays a small fixed size (a handful of
        // trusted devices/friends, not a public swarm).
        let max_files = ((capacity_bytes / (16 * 1024)).clamp(4, 4096)) as u32;
        let max_chain_records = ((max_files as u64 * 4).clamp(8, 16384)) as u32;
        let max_recipients = MAX_RECIPIENTS;

        let bitmap_len = BlockAllocator::bitmap_len_bytes(block_count);
        let file_table_len = max_files as u64 * ENTRY_SIZE as u64;
        let recipient_len = max_recipients as u64 * RECIPIENT_SLOT_SIZE as u64;
        let chain_len = max_chain_records as u64 * CHAIN_RECORD_SIZE as u64;

        let bitmap_offset = HEADER_SIZE;
        let file_table_offset = bitmap_offset + bitmap_len;
        let recipient_offset = file_table_offset + file_table_len;
        let chain_offset = recipient_offset + recipient_len;
        let data_offset = chain_offset + chain_len;

        let salt = crypto::random_salt();
        let argon2_params = Argon2Params::default();
        let kek = MasterKey::derive(password.as_bytes(), &salt, argon2_params)?;

        // The DEK is the vault's real content key -- independent of the
        // password, so it can also be wrapped for granted peer identities
        // later without ever touching the password.
        let mut dek = [0u8; 32];
        {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut dek);
        }
        let admin_key_slot = kek.encrypt_random_nonce(&dek, ADMIN_KEY_SLOT_AAD)?;
        if admin_key_slot.len() > ADMIN_KEY_SLOT_LEN {
            return Err(VaultError::CorruptContainer("admin key slot unexpectedly large"));
        }
        let content_key = MasterKey::from_bytes(dek);

        let admin_peer_id = admin_identity.peer_id();
        let created_at = now();
        let genesis_data_hash = crypto::sha256_concat(&[
            name.as_bytes(),
            description.as_bytes(),
            &capacity_bytes.to_le_bytes(),
            &admin_peer_id.signing_public,
        ]);
        let genesis = ChainRecord::new_signed(0, [0u8; 32], ChainOp::VaultCreated, 0, genesis_data_hash, created_at, &admin_identity);

        let header = Header {
            version: super::format::FORMAT_VERSION,
            flags: 0,
            block_size,
            block_count,
            capacity_bytes,
            name: name.to_string(),
            description: description.to_string(),
            created_at,
            salt,
            argon2_m_cost_kib: argon2_params.m_cost_kib,
            argon2_t_cost: argon2_params.t_cost,
            argon2_p_cost: argon2_params.p_cost,
            admin_key_slot,
            admin_signing_pubkey: admin_peer_id.signing_public,
            admin_encryption_pubkey: admin_peer_id.encryption_public,
            bitmap_offset,
            bitmap_len,
            file_table_offset,
            file_table_len,
            max_files,
            entry_size: ENTRY_SIZE,
            recipient_offset,
            recipient_len,
            max_recipients,
            recipient_slot_size: RECIPIENT_SLOT_SIZE,
            chain_offset,
            chain_len,
            max_chain_records,
            chain_record_size: CHAIN_RECORD_SIZE,
            chain_next_seq: 1,
            chain_last_hash: genesis.record_hash,
            data_offset,
        };

        let total_size = header.total_container_size();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        // The data region is only *logically* reserved: we grow the file to
        // its full size (so capacity checks and offsets are meaningful) but
        // rely on filesystem sparse-file support to avoid physically
        // allocating the whole capacity up front. Metadata regions
        // (bitmap/file table/recipients/chain) are explicitly zero-written
        // below so their contents never depend on sparse-hole semantics.
        file.set_len(total_size)?;

        file.write_all(&header.encode())?;

        let allocator = BlockAllocator::new(block_count);
        file.write_all(allocator.as_bytes())?; // zeroed bitmap

        let empty_entry = FileEntry::empty_slot();
        for _ in 0..max_files {
            file.write_all(&empty_entry)?;
        }

        let empty_recipient = RecipientSlot::empty_slot();
        for _ in 0..max_recipients {
            file.write_all(&empty_recipient)?;
        }

        file.write_all(&genesis.encode())?;
        for _ in 1..max_chain_records {
            file.write_all(&[0u8; CHAIN_RECORD_SIZE as usize])?;
        }

        file.flush()?;

        Ok(Vault { file, header, allocator, key: content_key, admin_identity: Some(admin_identity), change_log: Vec::new() })
    }

    /// Opens a vault as its admin, using the password. `local_identity`
    /// should be the caller's own persistent identity (see
    /// `Identity::load_or_create`); mutating methods only work if it
    /// matches the identity recorded as admin at creation time.
    pub fn open<P: AsRef<Path>>(path: P, password: &str, local_identity: Identity) -> Result<Vault> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        let mut header_buf = vec![0u8; HEADER_SIZE as usize];
        file.read_exact(&mut header_buf)?;
        let header = Header::decode(&header_buf)?;

        let params = Argon2Params {
            m_cost_kib: header.argon2_m_cost_kib,
            t_cost: header.argon2_t_cost,
            p_cost: header.argon2_p_cost,
        };
        let kek = MasterKey::derive(password.as_bytes(), &header.salt, params)?;
        let dek_bytes = kek.decrypt_random_nonce(&header.admin_key_slot, ADMIN_KEY_SLOT_AAD)?;
        if dek_bytes.len() != 32 {
            return Err(VaultError::CorruptContainer("unwrapped admin DEK has the wrong length"));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        let content_key = MasterKey::from_bytes(dek);

        let admin_identity = if local_identity.peer_id().signing_public == header.admin_signing_pubkey {
            Some(local_identity)
        } else {
            // The password was correct (that's what unwrapped the DEK
            // above), but this device's local identity doesn't match the
            // one recorded as admin at creation time -- e.g. the identity
            // file was regenerated. Content is still readable; authoring
            // new signed changes is not, until identity is reconciled.
            None
        };

        let mut bitmap_buf = vec![0u8; header.bitmap_len as usize];
        file.seek(SeekFrom::Start(header.bitmap_offset))?;
        file.read_exact(&mut bitmap_buf)?;
        let allocator = BlockAllocator::from_bytes(bitmap_buf, header.block_count);

        Ok(Vault { file, header, allocator, key: content_key, admin_identity, change_log: Vec::new() })
    }

    /// Opens a vault as a granted peer (no password): looks up
    /// `local_identity`'s recipient slot and unwraps the DEK via X25519.
    /// A recipient-opened vault can read/decrypt content but can never
    /// author changes (`admin_identity` is always `None`) -- per the
    /// "admin is superuser" model.
    pub fn open_as_recipient<P: AsRef<Path>>(path: P, local_identity: &Identity) -> Result<Vault> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        let mut header_buf = vec![0u8; HEADER_SIZE as usize];
        file.read_exact(&mut header_buf)?;
        let header = Header::decode(&header_buf)?;

        let my_encryption_public = local_identity.peer_id().encryption_public;
        let mut found_slot: Option<RecipientSlot> = None;
        for idx in 0..header.max_recipients {
            let mut buf = vec![0u8; header.recipient_slot_size as usize];
            file.seek(SeekFrom::Start(header.recipient_offset + idx as u64 * header.recipient_slot_size as u64))?;
            file.read_exact(&mut buf)?;
            let slot = RecipientSlot::decode(&buf)?;
            if slot.is_occupied() && slot.encryption_pubkey == my_encryption_public {
                found_slot = Some(slot);
                break;
            }
        }
        let slot = found_slot.ok_or(VaultError::AccessNotGranted)?;

        if slot.wrapped_dek.len() != crypto::WRAPPED_DEK_LEN {
            return Err(VaultError::CorruptContainer("recipient wrapped DEK has the wrong length"));
        }
        let mut wrapped = [0u8; crypto::WRAPPED_DEK_LEN];
        wrapped.copy_from_slice(&slot.wrapped_dek);
        let dek = crypto::unwrap_dek_for_recipient(local_identity.encryption_secret(), &wrapped)?;
        let content_key = MasterKey::from_bytes(dek);

        let mut bitmap_buf = vec![0u8; header.bitmap_len as usize];
        file.seek(SeekFrom::Start(header.bitmap_offset))?;
        file.read_exact(&mut bitmap_buf)?;
        let allocator = BlockAllocator::from_bytes(bitmap_buf, header.block_count);

        Ok(Vault { file, header, allocator, key: content_key, admin_identity: None, change_log: Vec::new() })
    }

    pub fn summary(&self) -> VaultSummary {
        VaultSummary {
            name: self.header.name.clone(),
            description: self.header.description.clone(),
            capacity_bytes: self.header.capacity_bytes,
            created_at: self.header.created_at,
        }
    }

    pub fn used_bytes(&self) -> u64 {
        self.allocator.occupied_count() * self.header.block_size as u64
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.header.capacity_bytes
    }

    /// True if this handle was opened/created with admin privileges
    /// (i.e. mutating methods will work).
    pub fn is_admin(&self) -> bool {
        self.admin_identity.is_some()
    }

    /// The vault's current chain position: `(next_seq, last_hash)`. This
    /// is exactly what a peer sends as `SyncMessage::ChainState` to
    /// report how caught-up they are.
    pub fn chain_state(&self) -> (u64, [u8; 32]) {
        (self.header.chain_next_seq, self.header.chain_last_hash)
    }

    fn require_admin(&self) -> Result<()> {
        if self.admin_identity.is_some() {
            Ok(())
        } else {
            Err(VaultError::NotAuthorized)
        }
    }

    // -----------------------------------------------------------------
    // Low-level region I/O
    // -----------------------------------------------------------------

    /// Writes `data` at `offset` and records the range in the change log.
    /// Every on-disk mutation in this module funnels through here (or
    /// through `write_physical_block`, which calls this) so the change
    /// log always reflects exactly what changed on disk.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        self.change_log.push((offset, data.to_vec()));
        Ok(())
    }

    /// Drains and returns every byte range written since the last call.
    /// Intended to be called right after a mutating method (`add_file`,
    /// `update_file`, `delete_file`, `grant_access`) to get exactly the
    /// patch that needs shipping to peers over the (future) network
    /// layer. Not meaningful after `revoke_access`, which rewrites nearly
    /// the whole file -- send a fresh full copy (see `export_full`)
    /// instead of a patch in that case.
    pub fn take_change_log(&mut self) -> Vec<(u64, Vec<u8>)> {
        std::mem::take(&mut self.change_log)
    }

    /// Returns the vault's entire underlying container as bytes, for
    /// transferring a full initial (or post-rotation) replica to a peer.
    pub fn export_full(&mut self) -> Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Applies a patch produced by [`Vault::take_change_log`] on another
    /// replica of the same vault: writes each range verbatim, then
    /// reloads the in-memory header/allocator from disk (they may have
    /// changed). The content key is untouched, since ordinary patches
    /// never change the DEK -- only `revoke_access`/`KeyRotated` does,
    /// which is synced via a full `export_full` transfer instead.
    pub fn apply_remote_patch(&mut self, ranges: &[(u64, Vec<u8>)]) -> Result<()> {
        for (offset, data) in ranges {
            self.file.seek(SeekFrom::Start(*offset))?;
            self.file.write_all(data)?;
        }
        self.file.flush()?;

        let mut header_buf = vec![0u8; HEADER_SIZE as usize];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut header_buf)?;
        self.header = Header::decode(&header_buf)?;

        let mut bitmap_buf = vec![0u8; self.header.bitmap_len as usize];
        self.file.seek(SeekFrom::Start(self.header.bitmap_offset))?;
        self.file.read_exact(&mut bitmap_buf)?;
        self.allocator = BlockAllocator::from_bytes(bitmap_buf, self.header.block_count);
        Ok(())
    }

    fn write_header(&mut self) -> Result<()> {
        let encoded = self.header.encode();
        self.write_at(0, &encoded)
    }

    fn write_bitmap(&mut self) -> Result<()> {
        let offset = self.header.bitmap_offset;
        let bytes = self.allocator.as_bytes().to_vec();
        self.write_at(offset, &bytes)
    }

    fn slot_offset(&self, idx: u32) -> u64 {
        self.header.file_table_offset + idx as u64 * self.header.entry_size as u64
    }

    fn read_slot(&mut self, idx: u32) -> Result<FileEntry> {
        let mut buf = vec![0u8; self.header.entry_size as usize];
        self.file.seek(SeekFrom::Start(self.slot_offset(idx)))?;
        self.file.read_exact(&mut buf)?;
        FileEntry::decode(&buf)
    }

    fn write_slot(&mut self, idx: u32, entry: &FileEntry) -> Result<()> {
        let offset = self.slot_offset(idx);
        let encoded = entry.encode();
        self.write_at(offset, &encoded)
    }

    fn recipient_slot_offset(&self, idx: u32) -> u64 {
        self.header.recipient_offset + idx as u64 * self.header.recipient_slot_size as u64
    }

    fn read_recipient_slot(&mut self, idx: u32) -> Result<RecipientSlot> {
        let mut buf = vec![0u8; self.header.recipient_slot_size as usize];
        self.file.seek(SeekFrom::Start(self.recipient_slot_offset(idx)))?;
        self.file.read_exact(&mut buf)?;
        RecipientSlot::decode(&buf)
    }

    fn write_recipient_slot(&mut self, idx: u32, slot: &RecipientSlot) -> Result<()> {
        let offset = self.recipient_slot_offset(idx);
        let encoded = slot.encode();
        self.write_at(offset, &encoded)
    }

    fn chain_slot_offset(&self, seq: u64) -> u64 {
        let slot = seq % self.header.max_chain_records as u64;
        self.header.chain_offset + slot * self.header.chain_record_size as u64
    }

    fn read_chain_slot_at_seq(&mut self, seq: u64) -> Result<Option<ChainRecord>> {
        let mut buf = vec![0u8; self.header.chain_record_size as usize];
        self.file.seek(SeekFrom::Start(self.chain_slot_offset(seq)))?;
        self.file.read_exact(&mut buf)?;
        ChainRecord::decode(&buf)
    }

    /// Appends a new, admin-signed record to the (bounded, ring-buffered)
    /// integrity chain and persists the header pointer/anchor hash. Only
    /// the chain slot and the fixed-size header are rewritten -- never
    /// the rest of the container. Requires admin privileges.
    fn append_signed_chain_record(&mut self, op: ChainOp, target_id: u128, data_hash: [u8; 32]) -> Result<()> {
        let seq = self.header.chain_next_seq;
        let prev_hash = self.header.chain_last_hash;
        let rec = {
            let admin = self.admin_identity.as_ref().ok_or(VaultError::NotAuthorized)?;
            ChainRecord::new_signed(seq, prev_hash, op, target_id, data_hash, now(), admin)
        };
        let offset = self.chain_slot_offset(seq);
        let encoded = rec.encode();
        self.write_at(offset, &encoded)?;
        self.header.chain_next_seq = seq + 1;
        self.header.chain_last_hash = rec.record_hash;
        self.write_header()
    }

    // -----------------------------------------------------------------
    // Block-level I/O for file content
    // -----------------------------------------------------------------

    fn plain_chunk_len(&self) -> u64 {
        self.header.block_size as u64 - BLOCK_FRAMING_OVERHEAD
    }

    fn write_physical_block(&mut self, physical_idx: u64, file_id: u128, plaintext: &[u8]) -> Result<()> {
        let ciphertext = self.key.encrypt_block(file_id, physical_idx, plaintext)?;
        let block_size = self.header.block_size as usize;
        if 4 + ciphertext.len() > block_size {
            return Err(VaultError::CorruptContainer("encrypted chunk exceeds block size"));
        }
        let mut buf = vec![0u8; block_size];
        buf[0..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
        buf[4..4 + ciphertext.len()].copy_from_slice(&ciphertext);
        let offset = self.header.data_offset + physical_idx * self.header.block_size as u64;
        self.write_at(offset, &buf)
    }

    fn read_physical_block(&mut self, physical_idx: u64, file_id: u128) -> Result<Vec<u8>> {
        let block_size = self.header.block_size as usize;
        let mut buf = vec![0u8; block_size];
        let offset = self.header.data_offset + physical_idx * self.header.block_size as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut buf)?;
        let plain_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        if 4 + plain_len > block_size {
            return Err(VaultError::CorruptContainer("stored block length exceeds block size"));
        }
        let ciphertext = &buf[4..];
        let needed = plain_len + 16;
        if needed > ciphertext.len() {
            return Err(VaultError::CorruptContainer("stored block truncated"));
        }
        self.key.decrypt_block(file_id, physical_idx, &ciphertext[..needed])
    }

    /// Writes an index (overflow pointer) block: `next` continuation
    /// pointer followed by a list of data-block indices.
    fn write_index_block(&mut self, physical_idx: u64, file_id: u128, next: u64, indices: &[u64]) -> Result<()> {
        let mut payload = Vec::with_capacity(INDEX_BLOCK_HEADER + indices.len() * 8);
        payload.extend_from_slice(&next.to_le_bytes());
        payload.extend_from_slice(&(indices.len() as u32).to_le_bytes());
        for i in indices {
            payload.extend_from_slice(&i.to_le_bytes());
        }
        self.write_physical_block(physical_idx, file_id, &payload)
    }

    fn read_index_block(&mut self, physical_idx: u64, file_id: u128) -> Result<(u64, Vec<u64>)> {
        let payload = self.read_physical_block(physical_idx, file_id)?;
        if payload.len() < INDEX_BLOCK_HEADER {
            return Err(VaultError::CorruptContainer("overflow index block too short"));
        }
        let next = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let count = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
        let mut indices = Vec::with_capacity(count);
        let mut pos = INDEX_BLOCK_HEADER;
        for _ in 0..count {
            if pos + 8 > payload.len() {
                return Err(VaultError::CorruptContainer("overflow index block truncated"));
            }
            indices.push(u64::from_le_bytes(payload[pos..pos + 8].try_into().unwrap()));
            pos += 8;
        }
        Ok((next, indices))
    }

    fn index_block_capacity(&self) -> u64 {
        (self.plain_chunk_len() - INDEX_BLOCK_HEADER as u64) / 8
    }

    /// Returns the ordered list of physical data-block indices for a file
    /// (direct blocks followed by every overflow chain block's contents).
    fn collect_data_blocks(&mut self, entry: &FileEntry) -> Result<Vec<u64>> {
        let data_block_count = if entry.size == 0 {
            0
        } else {
            entry.size.div_ceil(self.plain_chunk_len())
        };
        let direct_count = data_block_count.min(super::format::DIRECT_BLOCKS as u64) as usize;
        let mut blocks: Vec<u64> = entry.direct_blocks[..direct_count].to_vec();

        let mut next = entry.overflow_block;
        while next != 0 {
            let (n, indices) = self.read_index_block(next, entry.id)?;
            blocks.extend(indices);
            next = n;
        }

        if blocks.len() as u64 != data_block_count {
            return Err(VaultError::CorruptContainer(
                "file entry block count does not match recorded size",
            ));
        }
        Ok(blocks)
    }

    /// Collects every physical block (data + overflow index blocks)
    /// belonging to a file, for freeing on delete/update or re-encrypting
    /// on key rotation.
    fn collect_all_blocks(&mut self, entry: &FileEntry) -> Result<Vec<u64>> {
        let data_block_count = if entry.size == 0 {
            0
        } else {
            entry.size.div_ceil(self.plain_chunk_len())
        };
        let direct_count = data_block_count.min(super::format::DIRECT_BLOCKS as u64) as usize;
        let mut all: Vec<u64> = entry.direct_blocks[..direct_count].to_vec();

        let mut next = entry.overflow_block;
        while next != 0 {
            all.push(next);
            let (n, indices) = self.read_index_block(next, entry.id)?;
            all.extend(indices);
            next = n;
        }
        Ok(all)
    }

    // -----------------------------------------------------------------
    // File table helpers
    // -----------------------------------------------------------------

    fn find_slot_by_name(&mut self, name: &str) -> Result<Option<(u32, FileEntry)>> {
        for idx in 0..self.header.max_files {
            let entry = self.read_slot(idx)?;
            if entry.is_occupied() && entry.name == name {
                return Ok(Some((idx, entry)));
            }
        }
        Ok(None)
    }

    fn find_free_slot(&mut self) -> Result<Option<u32>> {
        for idx in 0..self.header.max_files {
            let entry = self.read_slot(idx)?;
            if !entry.is_occupied() {
                return Ok(Some(idx));
            }
        }
        Ok(None)
    }

    fn all_occupied_entries(&mut self) -> Result<Vec<(u32, FileEntry)>> {
        let mut out = Vec::new();
        for idx in 0..self.header.max_files {
            let entry = self.read_slot(idx)?;
            if entry.is_occupied() {
                out.push((idx, entry));
            }
        }
        Ok(out)
    }

    pub fn list_files(&mut self) -> Result<Vec<FileInfo>> {
        let mut out = Vec::new();
        for (_, entry) in self.all_occupied_entries()? {
            out.push(FileInfo {
                name: entry.name,
                size: entry.size,
                created_at: entry.created_at,
                modified_at: entry.modified_at,
            });
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Recipient (peer access) helpers
    // -----------------------------------------------------------------

    fn find_recipient_slot_by_signing_key(&mut self, signing_pubkey: &[u8; 32]) -> Result<Option<(u32, RecipientSlot)>> {
        for idx in 0..self.header.max_recipients {
            let slot = self.read_recipient_slot(idx)?;
            if slot.is_occupied() && &slot.signing_pubkey == signing_pubkey {
                return Ok(Some((idx, slot)));
            }
        }
        Ok(None)
    }

    fn find_free_recipient_slot(&mut self) -> Result<Option<u32>> {
        for idx in 0..self.header.max_recipients {
            let slot = self.read_recipient_slot(idx)?;
            if !slot.is_occupied() {
                return Ok(Some(idx));
            }
        }
        Ok(None)
    }

    pub fn list_recipients(&mut self) -> Result<Vec<RecipientInfo>> {
        let mut out = Vec::new();
        for idx in 0..self.header.max_recipients {
            let slot = self.read_recipient_slot(idx)?;
            if slot.is_occupied() {
                out.push(RecipientInfo {
                    peer_id: PeerId { signing_public: slot.signing_pubkey, encryption_public: slot.encryption_pubkey },
                    granted_at: slot.granted_at,
                });
            }
        }
        Ok(out)
    }

    /// Grants a peer identity decrypt access to this vault by wrapping
    /// the current DEK for their X25519 public key. Requires admin
    /// privileges. Does not touch any existing vault content.
    pub fn grant_access(&mut self, peer: &PeerId) -> Result<()> {
        self.require_admin()?;
        if self.find_recipient_slot_by_signing_key(&peer.signing_public)?.is_some() {
            return Err(VaultError::AlreadyGranted);
        }
        let idx = self.find_free_recipient_slot()?.ok_or(VaultError::RecipientTableFull)?;

        let wrapped = crypto::wrap_dek_for_recipient(&peer.encryption_public, self.key.expose_bytes())?;
        let slot = RecipientSlot {
            signing_pubkey: peer.signing_public,
            encryption_pubkey: peer.encryption_public,
            wrapped_dek: wrapped.to_vec(),
            granted_at: now(),
            flags: RECIPIENT_FLAG_OCCUPIED,
        };
        self.write_recipient_slot(idx, &slot)?;

        let target_id = peer_target_id(&peer.signing_public);
        let data_hash = crypto::sha256_concat(&[&peer.signing_public, &peer.encryption_public]);
        self.append_signed_chain_record(ChainOp::AccessGranted, target_id, data_hash)?;
        Ok(())
    }

    /// Revokes a peer's access. This is a *strict* revocation: it
    /// generates a brand-new DEK, re-encrypts every block currently in
    /// use under it, rewraps the new DEK for the admin and every
    /// remaining recipient, and drops the revoked peer's slot -- so the
    /// revoked peer's existing local copy becomes unreadable, not just
    /// "stops receiving updates." This is necessarily a full-vault
    /// operation (there's no way to make old ciphertext unreadable
    /// without changing the key that reads it), so unlike normal file
    /// operations it does briefly hold the whole vault's plaintext in
    /// memory during the swap.
    pub fn revoke_access(&mut self, peer_signing_pubkey: &[u8; 32], password: &str) -> Result<()> {
        self.require_admin()?;
        let (slot_idx, _) = self
            .find_recipient_slot_by_signing_key(peer_signing_pubkey)?
            .ok_or(VaultError::AccessNotGranted)?;

        // 1. Read every block currently in use, under the *current* key.
        let entries = self.all_occupied_entries()?;
        let mut block_plaintexts: Vec<(u64, u128, Vec<u8>)> = Vec::new();
        for (_, entry) in &entries {
            for &phys in &self.collect_all_blocks(entry)? {
                let plaintext = self.read_physical_block(phys, entry.id)?;
                block_plaintexts.push((phys, entry.id, plaintext));
            }
        }

        // 2. Generate the new DEK and swap it in.
        let mut new_dek = [0u8; 32];
        {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut new_dek);
        }
        self.key = MasterKey::from_bytes(new_dek);

        // 3. Re-encrypt every block in place under the new key.
        for (phys, file_id, plaintext) in &block_plaintexts {
            self.write_physical_block(*phys, *file_id, plaintext)?;
        }

        // 4. Drop the revoked peer's slot; rewrap the new DEK for every
        // remaining recipient (their public key is already on file, so no
        // interaction with them is required).
        self.write_recipient_slot(slot_idx, &RecipientSlot { signing_pubkey: [0; 32], encryption_pubkey: [0; 32], wrapped_dek: Vec::new(), granted_at: 0, flags: 0 })?;
        for idx in 0..self.header.max_recipients {
            let mut slot = self.read_recipient_slot(idx)?;
            if slot.is_occupied() {
                let rewrapped = crypto::wrap_dek_for_recipient(&slot.encryption_pubkey, &new_dek)?;
                slot.wrapped_dek = rewrapped.to_vec();
                self.write_recipient_slot(idx, &slot)?;
            }
        }

        // 5. Rewrap the new DEK for the admin's password and persist it.
        let params = Argon2Params {
            m_cost_kib: self.header.argon2_m_cost_kib,
            t_cost: self.header.argon2_t_cost,
            p_cost: self.header.argon2_p_cost,
        };
        let kek = MasterKey::derive(password.as_bytes(), &self.header.salt, params)?;
        let admin_key_slot = kek.encrypt_random_nonce(&new_dek, ADMIN_KEY_SLOT_AAD)?;
        self.header.admin_key_slot = admin_key_slot;
        self.write_header()?;

        let target_id = peer_target_id(peer_signing_pubkey);
        let data_hash = crypto::sha256(peer_signing_pubkey);
        self.append_signed_chain_record(ChainOp::KeyRotated, target_id, data_hash)?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // High-level file operations
    // -----------------------------------------------------------------

    fn store_new_content(
        &mut self,
        file_id: u128,
        data: &[u8],
    ) -> Result<([u64; super::format::DIRECT_BLOCKS], u64, u32)> {
        let chunk_len = self.plain_chunk_len();
        let data_block_count = if data.is_empty() {
            0
        } else {
            let n = data.len() as u64;
            n / chunk_len + if n % chunk_len != 0 { 1 } else { 0 }
        };

        let direct_needed = data_block_count.min(super::format::DIRECT_BLOCKS as u64);
        let excess = data_block_count.saturating_sub(super::format::DIRECT_BLOCKS as u64);
        let per_index_block = self.index_block_capacity();
        let index_blocks_needed = if excess == 0 { 0 } else { excess.div_ceil(per_index_block) };
        let total_needed = data_block_count + index_blocks_needed;

        if self.allocator.free_count() < total_needed {
            return Err(VaultError::InsufficientSpace {
                requested: total_needed * self.header.block_size as u64,
                available: self.allocator.free_count() * self.header.block_size as u64,
            });
        }

        let allocated = self.allocator.allocate(total_needed);
        debug_assert_eq!(allocated.len() as u64, total_needed);

        let data_blocks = &allocated[..data_block_count as usize];
        let index_blocks = &allocated[data_block_count as usize..];

        for (i, &phys) in data_blocks.iter().enumerate() {
            let start = i as u64 * chunk_len;
            let end = ((i as u64 + 1) * chunk_len).min(data.len() as u64);
            self.write_physical_block(phys, file_id, &data[start as usize..end as usize])?;
        }

        let mut direct_blocks = [0u64; super::format::DIRECT_BLOCKS];
        direct_blocks[..direct_needed as usize].copy_from_slice(&data_blocks[..direct_needed as usize]);

        let mut overflow_block = 0u64;
        if excess > 0 {
            let remaining_indices = &data_blocks[direct_needed as usize..];
            let mut chunks: Vec<&[u64]> = remaining_indices.chunks(per_index_block as usize).collect();
            if chunks.is_empty() {
                chunks.push(&[]);
            }
            for (i, idx_block_phys) in index_blocks.iter().enumerate() {
                let next = if i + 1 < index_blocks.len() { index_blocks[i + 1] } else { 0 };
                self.write_index_block(*idx_block_phys, file_id, next, chunks[i])?;
            }
            overflow_block = index_blocks[0];
        }

        self.write_bitmap()?;
        Ok((direct_blocks, overflow_block, total_needed as u32))
    }

    pub fn add_file(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.require_admin()?;
        if name.is_empty() || name.len() > MAX_FILENAME_LEN {
            return Err(VaultError::FieldTooLong);
        }
        if self.find_slot_by_name(name)?.is_some() {
            return Err(VaultError::FileAlreadyExists(name.to_string()));
        }
        let slot = self.find_free_slot()?.ok_or(VaultError::FileTableFull)?;

        let file_id = Uuid::now_v7().as_u128();
        let (direct_blocks, overflow_block, blocks_used) = self.store_new_content(file_id, data)?;
        let file_hash = crypto::sha256(data);
        let ts = now();

        let entry = FileEntry {
            id: file_id,
            name: name.to_string(),
            size: data.len() as u64,
            blocks_used,
            direct_blocks,
            overflow_block,
            file_hash,
            created_at: ts,
            modified_at: ts,
            flags: ENTRY_FLAG_OCCUPIED,
        };
        self.write_slot(slot, &entry)?;
        self.append_signed_chain_record(ChainOp::FileAdded, file_id, file_hash)?;
        Ok(())
    }

    pub fn read_file(&mut self, name: &str) -> Result<Vec<u8>> {
        let (_, entry) = self
            .find_slot_by_name(name)?
            .ok_or_else(|| VaultError::FileNotFound(name.to_string()))?;

        if entry.size == 0 {
            if entry.file_hash != crypto::sha256(&[]) {
                return Err(VaultError::IntegrityViolation("empty file hash mismatch"));
            }
            return Ok(Vec::new());
        }

        let blocks = self.collect_data_blocks(&entry)?;
        let mut out = Vec::with_capacity(entry.size as usize);
        for &phys in &blocks {
            let chunk = self.read_physical_block(phys, entry.id)?;
            out.extend_from_slice(&chunk);
        }
        out.truncate(entry.size as usize);

        if crypto::sha256(&out) != entry.file_hash {
            return Err(VaultError::IntegrityViolation(
                "file contents do not match stored hash (corruption or tampering)",
            ));
        }
        Ok(out)
    }

    pub fn update_file(&mut self, name: &str, new_data: &[u8]) -> Result<()> {
        self.require_admin()?;
        let (slot, old_entry) = self
            .find_slot_by_name(name)?
            .ok_or_else(|| VaultError::FileNotFound(name.to_string()))?;

        let old_blocks = self.collect_all_blocks(&old_entry)?;

        let chunk_len = self.plain_chunk_len();
        let new_data_blocks = if new_data.is_empty() {
            0
        } else {
            let n = new_data.len() as u64;
            n / chunk_len + if n % chunk_len != 0 { 1 } else { 0 }
        };
        let excess = new_data_blocks.saturating_sub(super::format::DIRECT_BLOCKS as u64);
        let per_index_block = self.index_block_capacity();
        let index_blocks_needed = if excess == 0 { 0 } else { excess.div_ceil(per_index_block) };
        let total_needed = new_data_blocks + index_blocks_needed;
        let available_after_free = self.allocator.free_count() + old_blocks.len() as u64;
        if available_after_free < total_needed {
            return Err(VaultError::InsufficientSpace {
                requested: total_needed * self.header.block_size as u64,
                available: available_after_free * self.header.block_size as u64,
            });
        }

        // Free the old blocks first, then allocate fresh ones for the new
        // content. Only this file's blocks and its single file-table slot
        // are touched -- every other file's blocks are left untouched.
        self.allocator.free(&old_blocks);
        self.write_bitmap()?;

        let (direct_blocks, overflow_block, blocks_used) = self.store_new_content(old_entry.id, new_data)?;
        let file_hash = crypto::sha256(new_data);

        let entry = FileEntry {
            id: old_entry.id,
            name: old_entry.name.clone(),
            size: new_data.len() as u64,
            blocks_used,
            direct_blocks,
            overflow_block,
            file_hash,
            created_at: old_entry.created_at,
            modified_at: now(),
            flags: ENTRY_FLAG_OCCUPIED,
        };
        self.write_slot(slot, &entry)?;
        self.append_signed_chain_record(ChainOp::FileUpdated, entry.id, file_hash)?;
        Ok(())
    }

    pub fn delete_file(&mut self, name: &str) -> Result<()> {
        self.require_admin()?;
        let (slot, entry) = self
            .find_slot_by_name(name)?
            .ok_or_else(|| VaultError::FileNotFound(name.to_string()))?;
        let blocks = self.collect_all_blocks(&entry)?;
        self.allocator.free(&blocks);
        self.write_bitmap()?;

        let mut tombstone = entry.clone();
        tombstone.flags = ENTRY_FLAG_DELETED;
        self.write_slot(slot, &tombstone)?;

        let data_hash = crypto::sha256(entry.name.as_bytes());
        self.append_signed_chain_record(ChainOp::FileDeleted, entry.id, data_hash)?;
        Ok(())
    }

    /// Verifies the tamper-evident hash chain (linkage, self-hashes, and
    /// each record's admin signature, over whatever window of records is
    /// currently retained in the bounded, ring-buffered chain region) and
    /// every stored file's content hash.
    pub fn verify_integrity(&mut self) -> Result<()> {
        let window = self.header.max_chain_records as u64;
        let newest_seq = self.header.chain_next_seq.saturating_sub(1);
        let oldest_seq = newest_seq.saturating_sub(window.saturating_sub(1));
        let admin_signing_pubkey = self.header.admin_signing_pubkey;

        let mut prev: Option<ChainRecord> = None;
        for seq in oldest_seq..=newest_seq {
            let rec = match self.read_chain_slot_at_seq(seq)? {
                Some(r) => r,
                None => continue,
            };
            if rec.seq != seq {
                return Err(VaultError::IntegrityViolation(
                    "chain record sequence number does not match its slot",
                ));
            }
            if !rec.verify_self() {
                return Err(VaultError::IntegrityViolation(
                    "chain record hash does not match its own contents",
                ));
            }
            rec.verify_signature(&admin_signing_pubkey)?;
            if let Some(p) = &prev {
                if rec.prev_hash != p.record_hash {
                    return Err(VaultError::IntegrityViolation(
                        "chain record does not link to the previous record's hash",
                    ));
                }
            }
            prev = Some(rec);
        }
        if let Some(last) = &prev {
            if last.record_hash != self.header.chain_last_hash {
                return Err(VaultError::IntegrityViolation(
                    "chain anchor in header does not match the latest chain record",
                ));
            }
        }

        let names: Vec<String> = self.list_files()?.into_iter().map(|f| f.name).collect();
        for name in names {
            self.read_file(&name)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn small_capacity() -> u64 {
        // 64 blocks at 4096 bytes = 256 KiB of data capacity: enough for
        // exercising direct + overflow storage without slow tests.
        256 * 1024
    }

    #[test]
    fn create_then_open_with_correct_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        {
            let admin = Identity::generate();
            let _v = Vault::create(&path, "My Vault", "desc", small_capacity(), "correct horse", admin).unwrap();
        }
        let admin_again = Identity::generate(); // different identity, but password path doesn't require a match to open
        let v = Vault::open(&path, "correct horse", admin_again).unwrap();
        let s = v.summary();
        assert_eq!(s.name, "My Vault");
        assert_eq!(s.description, "desc");
        // Identity didn't match the recorded admin, so this handle can
        // read but not author new changes.
        assert!(!v.is_admin());
    }

    #[test]
    fn reopening_with_the_same_identity_keeps_admin_rights() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let admin = Identity::generate();
        let admin_bytes = admin.to_bytes();
        Vault::create(&path, "V", "d", small_capacity(), "pw", admin).unwrap();

        let same_admin = Identity::from_bytes(&admin_bytes);
        let v = Vault::open(&path, "pw", same_admin).unwrap();
        assert!(v.is_admin());
    }

    #[test]
    fn open_rejects_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        Vault::create(&path, "V", "d", small_capacity(), "right-pw", Identity::generate()).unwrap();
        let err = Vault::open(&path, "wrong-pw", Identity::generate()).unwrap_err();
        assert!(matches!(err, VaultError::IncorrectPassword));
    }

    #[test]
    fn create_rejects_capacity_smaller_than_one_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let err = Vault::create(&path, "V", "d", 10, "pw", Identity::generate()).unwrap_err();
        assert!(matches!(err, VaultError::CapacityTooSmall));
    }

    #[test]
    fn add_and_read_small_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("hello.txt", b"hello, world!").unwrap();
        let data = v.read_file("hello.txt").unwrap();
        assert_eq!(data, b"hello, world!");
    }

    #[test]
    fn non_admin_handle_cannot_mutate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        // Opened with a *different* identity than the recorded admin.
        let mut v = Vault::open(&path, "pw", Identity::generate()).unwrap();
        assert!(!v.is_admin());
        assert!(matches!(v.add_file("x.txt", b"data"), Err(VaultError::NotAuthorized)));
    }

    #[test]
    fn add_reject_duplicate_name() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("a.txt", b"1").unwrap();
        let err = v.add_file("a.txt", b"2").unwrap_err();
        assert!(matches!(err, VaultError::FileAlreadyExists(_)));
    }

    #[test]
    fn read_missing_file_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        let err = v.read_file("nope.txt").unwrap_err();
        assert!(matches!(err, VaultError::FileNotFound(_)));
    }

    #[test]
    fn add_empty_file_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("empty.txt", b"").unwrap();
        let data = v.read_file("empty.txt").unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn fragmented_large_file_spans_overflow_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        let payload = vec![0xABu8; 4076 * 12 + 37];
        v.add_file("big.bin", &payload).unwrap();
        let read_back = v.read_file("big.bin").unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn update_file_replaces_contents_and_frees_old_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("f.txt", &vec![1u8; 4076 * 3]).unwrap();
        let used_before = v.used_bytes();

        v.update_file("f.txt", b"tiny now").unwrap();
        let data = v.read_file("f.txt").unwrap();
        assert_eq!(data, b"tiny now");
        assert!(v.used_bytes() < used_before, "old blocks should have been freed");
    }

    #[test]
    fn update_missing_file_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        let err = v.update_file("nope.txt", b"x").unwrap_err();
        assert!(matches!(err, VaultError::FileNotFound(_)));
    }

    #[test]
    fn delete_file_frees_space_and_removes_from_listing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("f.txt", b"some content").unwrap();
        assert_eq!(v.list_files().unwrap().len(), 1);
        v.delete_file("f.txt").unwrap();
        assert_eq!(v.list_files().unwrap().len(), 0);
        assert!(v.read_file("f.txt").is_err());
    }

    #[test]
    fn capacity_enforcement_rejects_oversized_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", 64 * 1024, "pw", Identity::generate()).unwrap(); // 16 blocks
        let too_big = vec![0u8; 64 * 1024 * 2];
        let err = v.add_file("huge.bin", &too_big).unwrap_err();
        assert!(matches!(err, VaultError::InsufficientSpace { .. }));
    }

    #[test]
    fn reopen_after_close_preserves_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let admin = Identity::generate();
        let admin_bytes = admin.to_bytes();
        {
            let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", admin).unwrap();
            v.add_file("a.txt", b"alpha").unwrap();
            v.add_file("b.txt", b"beta").unwrap();
        }
        let mut v = Vault::open(&path, "pw", Identity::from_bytes(&admin_bytes)).unwrap();
        assert_eq!(v.read_file("a.txt").unwrap(), b"alpha");
        assert_eq!(v.read_file("b.txt").unwrap(), b"beta");
    }

    #[test]
    fn verify_integrity_passes_on_healthy_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("a.txt", b"alpha").unwrap();
        v.update_file("a.txt", b"alpha-2").unwrap();
        v.add_file("b.txt", b"beta").unwrap();
        v.delete_file("b.txt").unwrap();
        v.verify_integrity().unwrap();
    }

    #[test]
    fn verify_integrity_detects_flipped_byte_in_data_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let admin = Identity::generate();
        let admin_bytes = admin.to_bytes();
        {
            let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", admin).unwrap();
            v.add_file("a.txt", b"alpha-content-here").unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        // Corrupt a byte a few bytes into the first data block (past its
        // 4-byte plaintext-length prefix, into the actual ciphertext).
        // Computed from the real on-disk header rather than a hardcoded
        // offset, so this doesn't go stale if a region's size changes.
        let header = super::super::format::Header::decode(&bytes[..super::super::format::HEADER_SIZE as usize]).unwrap();
        let data_start = header.data_offset as usize + 4;
        bytes[data_start] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();

        let mut v = Vault::open(&path, "pw", Identity::from_bytes(&admin_bytes)).unwrap();
        let err = v.verify_integrity().unwrap_err();
        assert!(matches!(
            err,
            VaultError::CorruptContainer(_) | VaultError::IntegrityViolation(_)
        ));
    }

    #[test]
    fn open_rejects_non_rvlt_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("not-a-vault.rvlt");
        std::fs::write(&path, b"just some random bytes, not a vault at all").unwrap();
        let err = Vault::open(&path, "pw", Identity::generate()).unwrap_err();
        assert!(matches!(err, VaultError::NotARvltFile | VaultError::Io(_)));
    }

    #[test]
    fn peek_summary_does_not_require_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        Vault::create(&path, "Peekable", "desc", small_capacity(), "pw", Identity::generate()).unwrap();
        let summary = Vault::peek_summary(&path).unwrap();
        assert_eq!(summary.name, "Peekable");
    }

    #[test]
    fn single_file_invariant_no_sidecar_created() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("a.txt", b"alpha").unwrap();
        drop(v);
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "no sidecar files should exist next to the .rvlt file");
    }

    // ---- Network / envelope-encryption tests ----

    #[test]
    fn grant_access_lets_peer_open_and_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("secret.txt", b"shared content").unwrap();

        let peer = Identity::generate();
        v.grant_access(&peer.peer_id()).unwrap();
        drop(v);

        let mut peer_view = Vault::open_as_recipient(&path, &peer).unwrap();
        assert!(!peer_view.is_admin());
        assert_eq!(peer_view.read_file("secret.txt").unwrap(), b"shared content");
    }

    #[test]
    fn peer_without_grant_cannot_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();

        let stranger = Identity::generate();
        let err = Vault::open_as_recipient(&path, &stranger).unwrap_err();
        assert!(matches!(err, VaultError::AccessNotGranted));
    }

    #[test]
    fn granting_same_peer_twice_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        let peer = Identity::generate().peer_id();
        v.grant_access(&peer).unwrap();
        assert!(matches!(v.grant_access(&peer), Err(VaultError::AlreadyGranted)));
    }

    #[test]
    fn revoke_access_rotates_key_and_locks_out_the_peer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("secret.txt", b"shared content").unwrap();

        let peer = Identity::generate();
        v.grant_access(&peer.peer_id()).unwrap();

        // Peer can read before revocation.
        {
            let mut peer_view = Vault::open_as_recipient(&path, &peer).unwrap();
            assert_eq!(peer_view.read_file("secret.txt").unwrap(), b"shared content");
        }

        v.revoke_access(&peer.peer_id().signing_public, "pw").unwrap();
        drop(v);

        // Peer can no longer open the vault at all -- their slot is gone.
        let err = Vault::open_as_recipient(&path, &peer).unwrap_err();
        assert!(matches!(err, VaultError::AccessNotGranted));
    }

    #[test]
    fn revoke_access_preserves_content_for_admin_and_other_recipients() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let admin = Identity::generate();
        let admin_bytes = admin.to_bytes();
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", admin).unwrap();
        v.add_file("secret.txt", b"shared content").unwrap();

        let revoked_peer = Identity::generate();
        let kept_peer = Identity::generate();
        v.grant_access(&revoked_peer.peer_id()).unwrap();
        v.grant_access(&kept_peer.peer_id()).unwrap();

        v.revoke_access(&revoked_peer.peer_id().signing_public, "pw").unwrap();

        // Admin still reads fine after rotation.
        assert_eq!(v.read_file("secret.txt").unwrap(), b"shared content");
        drop(v);

        // Reopening as admin still works.
        let mut reopened = Vault::open(&path, "pw", Identity::from_bytes(&admin_bytes)).unwrap();
        assert_eq!(reopened.read_file("secret.txt").unwrap(), b"shared content");

        // The peer who was NOT revoked still has working access post-rotation.
        let mut kept_view = Vault::open_as_recipient(&path, &kept_peer).unwrap();
        assert_eq!(kept_view.read_file("secret.txt").unwrap(), b"shared content");
    }

    #[test]
    fn revoke_unknown_peer_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        let stranger = Identity::generate();
        let err = v.revoke_access(&stranger.peer_id().signing_public, "pw").unwrap_err();
        assert!(matches!(err, VaultError::AccessNotGranted));
    }

    #[test]
    fn verify_integrity_covers_grant_and_rotation_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("a.txt", b"alpha").unwrap();
        let peer = Identity::generate();
        v.grant_access(&peer.peer_id()).unwrap();
        v.revoke_access(&peer.peer_id().signing_public, "pw").unwrap();
        v.verify_integrity().unwrap();
    }

    #[test]
    fn update_file_does_not_affect_other_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("a.txt", b"alpha original").unwrap();
        v.add_file("b.txt", b"beta original").unwrap();

        v.update_file("a.txt", b"alpha REPLACED").unwrap();

        assert_eq!(v.read_file("a.txt").unwrap(), b"alpha REPLACED");
        assert_eq!(v.read_file("b.txt").unwrap(), b"beta original", "unrelated file must be untouched");
    }

    #[test]
    fn grant_access_fails_when_recipient_table_full() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();

        for _ in 0..MAX_RECIPIENTS {
            v.grant_access(&Identity::generate().peer_id()).unwrap();
        }
        let one_too_many = Identity::generate().peer_id();
        let err = v.grant_access(&one_too_many).unwrap_err();
        assert!(matches!(err, VaultError::RecipientTableFull));
    }

    #[test]
    fn delete_then_readd_same_name_uses_latest_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();

        v.add_file("a.txt", b"first version").unwrap();
        v.delete_file("a.txt").unwrap();
        v.add_file("a.txt", b"second version, different length!").unwrap();

        assert_eq!(v.read_file("a.txt").unwrap(), b"second version, different length!");
        assert_eq!(v.list_files().unwrap().len(), 1);
    }

    #[test]
    fn used_bytes_returns_to_baseline_after_delete() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        let baseline = v.used_bytes();

        v.add_file("big.bin", &vec![7u8; 4076 * 5]).unwrap();
        assert!(v.used_bytes() > baseline, "adding a file should consume blocks");

        v.delete_file("big.bin").unwrap();
        assert_eq!(v.used_bytes(), baseline, "deleting should free exactly what was allocated");
    }

    #[test]
    fn sequential_updates_do_not_leak_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();
        v.add_file("f.txt", &vec![1u8; 4076 * 2]).unwrap();
        let steady_state = v.used_bytes();

        for i in 0..10u8 {
            v.update_file("f.txt", &vec![i; 4076 * 2]).unwrap();
            assert_eq!(v.used_bytes(), steady_state, "same-size update should not grow used space over repeated calls");
        }
    }

    #[test]
    fn chain_survives_many_operations_past_the_retained_window() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw", Identity::generate()).unwrap();

        // small_capacity() gives max_chain_records = 64 (see Vault::create's
        // sizing formula); push well past that so old records roll off the
        // ring buffer and verify_integrity still succeeds over whatever
        // window remains.
        for i in 0..40 {
            let name = format!("f{i}.txt");
            v.add_file(&name, b"tiny").unwrap();
            v.delete_file(&name).unwrap();
        }
        v.add_file("final.txt", b"still here").unwrap();

        v.verify_integrity().unwrap();
        assert_eq!(v.read_file("final.txt").unwrap(), b"still here");
    }
}
