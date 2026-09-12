//! High-level `Vault` API: the single entry point that ties the binary
//! format, block allocator, crypto, and hash chain together into
//! create / open / add_file / read_file / update_file / delete_file /
//! verify_integrity operations.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::allocator::BlockAllocator;
use super::crypto::{self, Argon2Params, MasterKey};
use super::error::{Result, VaultError};
use super::format::{
    ChainOp, ChainRecord, FileEntry, Header, CHAIN_RECORD_SIZE, ENTRY_FLAG_DELETED,
    ENTRY_FLAG_OCCUPIED, ENTRY_SIZE, HEADER_SIZE, MAX_FILENAME_LEN,
};

/// Per-block on-disk framing overhead: a 4-byte plaintext-length prefix plus
/// the 16-byte AES-GCM authentication tag.
const BLOCK_FRAMING_OVERHEAD: u64 = 4 + 16;
/// Bytes reserved at the front of an overflow index block for `next` (u64)
/// and `count` (u32).
const INDEX_BLOCK_HEADER: usize = 12;

const VERIFIER_PLAINTEXT: &[u8] = b"revault-ok";
const VERIFIER_AAD: &[u8] = b"revault-verifier";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

pub struct Vault {
    file: File,
    header: Header,
    allocator: BlockAllocator,
    key: MasterKey,
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

        // Scale metadata region sizes with capacity, within sane bounds, so
        // a 10 MB test vault and a 1 TB real vault both get a reasonably
        // sized (but bounded) file table and chain log.
        let max_files = ((capacity_bytes / (16 * 1024)).clamp(4, 4096)) as u32;
        let max_chain_records = ((max_files as u64 * 4).clamp(8, 16384)) as u32;

        let bitmap_len = BlockAllocator::bitmap_len_bytes(block_count);
        let file_table_len = max_files as u64 * ENTRY_SIZE as u64;
        let chain_len = max_chain_records as u64 * CHAIN_RECORD_SIZE as u64;

        let bitmap_offset = HEADER_SIZE;
        let file_table_offset = bitmap_offset + bitmap_len;
        let chain_offset = file_table_offset + file_table_len;
        let data_offset = chain_offset + chain_len;

        let salt = crypto::random_salt();
        let argon2_params = Argon2Params::default();
        let key = MasterKey::derive(password.as_bytes(), &salt, argon2_params)?;
        let verifier_blob = key.encrypt_random_nonce(VERIFIER_PLAINTEXT, VERIFIER_AAD)?;

        let created_at = now();
        let genesis_data_hash =
            crypto::sha256_concat(&[name.as_bytes(), description.as_bytes(), &capacity_bytes.to_le_bytes()]);
        let genesis = ChainRecord::new(0, [0u8; 32], ChainOp::VaultCreated, 0, genesis_data_hash, created_at);

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
            verifier_blob,
            bitmap_offset,
            bitmap_len,
            file_table_offset,
            file_table_len,
            max_files,
            entry_size: ENTRY_SIZE,
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
        // (bitmap/file table/chain) are explicitly zero-written below so
        // their contents never depend on sparse-hole semantics.
        file.set_len(total_size)?;

        file.write_all(&header.encode())?;

        let allocator = BlockAllocator::new(block_count);
        file.write_all(allocator.as_bytes())?; // zeroed bitmap

        let empty_entry = FileEntry::empty_slot();
        for _ in 0..max_files {
            file.write_all(&empty_entry)?;
        }

        file.write_all(&genesis.encode())?;
        for _ in 1..max_chain_records {
            file.write_all(&[0u8; CHAIN_RECORD_SIZE as usize])?;
        }

        file.flush()?;

        Ok(Vault { file, header, allocator, key })
    }

    pub fn open<P: AsRef<Path>>(path: P, password: &str) -> Result<Vault> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        let mut header_buf = vec![0u8; HEADER_SIZE as usize];
        file.read_exact(&mut header_buf)?;
        let header = Header::decode(&header_buf)?;

        let params = Argon2Params {
            m_cost_kib: header.argon2_m_cost_kib,
            t_cost: header.argon2_t_cost,
            p_cost: header.argon2_p_cost,
        };
        let key = MasterKey::derive(password.as_bytes(), &header.salt, params)?;
        let decrypted = key.decrypt_random_nonce(&header.verifier_blob, VERIFIER_AAD)?;
        if decrypted != VERIFIER_PLAINTEXT {
            return Err(VaultError::IncorrectPassword);
        }

        let mut bitmap_buf = vec![0u8; header.bitmap_len as usize];
        file.seek(SeekFrom::Start(header.bitmap_offset))?;
        file.read_exact(&mut bitmap_buf)?;
        let allocator = BlockAllocator::from_bytes(bitmap_buf, header.block_count);

        Ok(Vault { file, header, allocator, key })
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

    // -----------------------------------------------------------------
    // Low-level region I/O
    // -----------------------------------------------------------------

    fn write_header(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.encode())?;
        Ok(())
    }

    fn write_bitmap(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(self.header.bitmap_offset))?;
        self.file.write_all(self.allocator.as_bytes())?;
        Ok(())
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
        self.file.seek(SeekFrom::Start(self.slot_offset(idx)))?;
        self.file.write_all(&entry.encode())?;
        Ok(())
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

    /// Appends a new record to the (bounded, ring-buffered) integrity
    /// chain and persists the header pointer/anchor hash. Only the chain
    /// slot and the fixed-size header are rewritten -- never the rest of
    /// the container.
    fn append_chain_record(&mut self, op: ChainOp, target_id: u128, data_hash: [u8; 32]) -> Result<()> {
        let seq = self.header.chain_next_seq;
        let rec = ChainRecord::new(seq, self.header.chain_last_hash, op, target_id, data_hash, now());
        let offset = self.chain_slot_offset(seq);
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&rec.encode())?;
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
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&buf)?;
        Ok(())
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
        // ciphertext buffer includes trailing padding; decrypt_block only
        // needs plaintext_len + 16 (tag) bytes of it, but AES-GCM will
        // simply fail to authenticate if we hand it the wrong length, so
        // trim precisely first.
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
            entry.size.div_ceil(self.header.block_size as u64)
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
    /// belonging to a file, for freeing on delete/update.
    fn collect_all_blocks(&mut self, entry: &FileEntry) -> Result<Vec<u64>> {
        let data_block_count = if entry.size == 0 {
            0
        } else {
            entry.size.div_ceil(self.header.block_size as u64)
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

    pub fn list_files(&mut self) -> Result<Vec<FileInfo>> {
        let mut out = Vec::new();
        for idx in 0..self.header.max_files {
            let entry = self.read_slot(idx)?;
            if entry.is_occupied() {
                out.push(FileInfo {
                    name: entry.name,
                    size: entry.size,
                    created_at: entry.created_at,
                    modified_at: entry.modified_at,
                });
            }
        }
        Ok(out)
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

        // Write file content chunks into the data blocks.
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
        self.append_chain_record(ChainOp::FileAdded, file_id, file_hash)?;
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
        let (slot, old_entry) = self
            .find_slot_by_name(name)?
            .ok_or_else(|| VaultError::FileNotFound(name.to_string()))?;

        let old_blocks = self.collect_all_blocks(&old_entry)?;

        // Check there's enough *additional* space, accounting for the
        // blocks this update will free.
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
        self.append_chain_record(ChainOp::FileUpdated, entry.id, file_hash)?;
        Ok(())
    }

    pub fn delete_file(&mut self, name: &str) -> Result<()> {
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
        self.append_chain_record(ChainOp::FileDeleted, entry.id, data_hash)?;
        Ok(())
    }

    /// Verifies the tamper-evident hash chain (over whatever window of
    /// records is currently retained in the bounded, ring-buffered chain
    /// region) and every stored file's content hash.
    pub fn verify_integrity(&mut self) -> Result<()> {
        // 1. Chain linkage, for the retained window of records.
        let window = self.header.max_chain_records as u64;
        let newest_seq = self.header.chain_next_seq.saturating_sub(1);
        let oldest_seq = newest_seq.saturating_sub(window.saturating_sub(1));

        let mut prev: Option<ChainRecord> = None;
        for seq in oldest_seq..=newest_seq {
            let rec = match self.read_chain_slot_at_seq(seq)? {
                Some(r) => r,
                None => continue, // slot was never written (short chain)
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

        // 2. Every occupied file's content still matches its stored hash.
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
            let _v = Vault::create(&path, "My Vault", "desc", small_capacity(), "correct horse").unwrap();
        }
        let v = Vault::open(&path, "correct horse").unwrap();
        let s = v.summary();
        assert_eq!(s.name, "My Vault");
        assert_eq!(s.description, "desc");
    }

    #[test]
    fn open_rejects_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        Vault::create(&path, "V", "d", small_capacity(), "right-pw").unwrap();
        let err = Vault::open(&path, "wrong-pw").unwrap_err();
        assert!(matches!(err, VaultError::IncorrectPassword));
    }

    #[test]
    fn create_rejects_capacity_smaller_than_one_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let err = Vault::create(&path, "V", "d", 10, "pw").unwrap_err();
        assert!(matches!(err, VaultError::CapacityTooSmall));
    }

    #[test]
    fn add_and_read_small_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        v.add_file("hello.txt", b"hello, world!").unwrap();
        let data = v.read_file("hello.txt").unwrap();
        assert_eq!(data, b"hello, world!");
    }

    #[test]
    fn add_reject_duplicate_name() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        v.add_file("a.txt", b"1").unwrap();
        let err = v.add_file("a.txt", b"2").unwrap_err();
        assert!(matches!(err, VaultError::FileAlreadyExists(_)));
    }

    #[test]
    fn read_missing_file_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        let err = v.read_file("nope.txt").unwrap_err();
        assert!(matches!(err, VaultError::FileNotFound(_)));
    }

    #[test]
    fn add_empty_file_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        v.add_file("empty.txt", b"").unwrap();
        let data = v.read_file("empty.txt").unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn fragmented_large_file_spans_overflow_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        // plain_chunk_len is 4096-20=4076 bytes; use > 8 blocks worth of
        // data so it must spill into the overflow index-block chain.
        let payload = vec![0xABu8; 4076 * 12 + 37];
        v.add_file("big.bin", &payload).unwrap();
        let read_back = v.read_file("big.bin").unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn update_file_replaces_contents_and_frees_old_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
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
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        let err = v.update_file("nope.txt", b"x").unwrap_err();
        assert!(matches!(err, VaultError::FileNotFound(_)));
    }

    #[test]
    fn delete_file_frees_space_and_removes_from_listing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
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
        let mut v = Vault::create(&path, "V", "d", 64 * 1024, "pw").unwrap(); // 16 blocks
        let too_big = vec![0u8; 64 * 1024 * 2];
        let err = v.add_file("huge.bin", &too_big).unwrap_err();
        assert!(matches!(err, VaultError::InsufficientSpace { .. }));
    }

    #[test]
    fn reopen_after_close_preserves_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        {
            let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
            v.add_file("a.txt", b"alpha").unwrap();
            v.add_file("b.txt", b"beta").unwrap();
        }
        let mut v = Vault::open(&path, "pw").unwrap();
        assert_eq!(v.read_file("a.txt").unwrap(), b"alpha");
        assert_eq!(v.read_file("b.txt").unwrap(), b"beta");
    }

    #[test]
    fn verify_integrity_passes_on_healthy_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
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
        {
            let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
            v.add_file("a.txt", b"alpha-content-here").unwrap();
        }
        // Corrupt one byte inside the data region on disk.
        let mut bytes = std::fs::read(&path).unwrap();
        let data_start = super::super::format::HEADER_SIZE as usize + 4096; // well past metadata regions, into data
        bytes[data_start] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();

        let mut v = Vault::open(&path, "pw").unwrap();
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
        let err = Vault::open(&path, "pw").unwrap_err();
        assert!(matches!(err, VaultError::NotARvltFile | VaultError::Io(_)));
    }

    #[test]
    fn peek_summary_does_not_require_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        Vault::create(&path, "Peekable", "desc", small_capacity(), "pw").unwrap();
        let summary = Vault::peek_summary(&path).unwrap();
        assert_eq!(summary.name, "Peekable");
    }

    #[test]
    fn single_file_invariant_no_sidecar_created() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.rvlt");
        let mut v = Vault::create(&path, "V", "d", small_capacity(), "pw").unwrap();
        v.add_file("a.txt", b"alpha").unwrap();
        drop(v);
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "no sidecar files should exist next to the .rvlt file");
    }
}
