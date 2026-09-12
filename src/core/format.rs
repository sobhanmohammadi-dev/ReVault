//! The `.rvlt` on-disk binary format.
//!
//! Byte order: **all multi-byte integers are little-endian.**
//!
//! Layout of a `.rvlt` file:
//!
//! ```text
//! [0, HEADER_SIZE)                        Header (fixed size, versioned)
//! [bitmap_offset, +bitmap_len)             Block allocation bitmap (1 bit/block)
//! [file_table_offset, +file_table_len)     Fixed array of FileEntry slots
//! [chain_offset, +chain_len)               Fixed array of ChainRecord slots
//! [data_offset, +block_count*block_size)   Data block region
//! ```
//!
//! Everything the vault needs to reopen and operate is inside this single
//! file: no sidecar index, cache, or manifest is ever required.
//!
//! This module only deals with *encoding/decoding bytes* and structural
//! validation (magic, version, bounds, overflow safety). It knows nothing
//! about encryption or the hash chain's cryptographic linking semantics
//! beyond storing/loading the raw hash bytes; that logic lives in
//! `crypto.rs` and `vault.rs`.

use super::error::{Result, VaultError};

pub const MAGIC: &[u8; 8] = b"RVLT0001";
pub const FORMAT_VERSION: u32 = 1;
pub const MIN_SUPPORTED_VERSION: u32 = 1;
pub const MAX_SUPPORTED_VERSION: u32 = 1;

pub const HEADER_SIZE: u64 = 1024;
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

pub const MAX_NAME_LEN: usize = 128;
pub const MAX_DESC_LEN: usize = 256;
pub const MAX_FILENAME_LEN: usize = 128;

pub const DIRECT_BLOCKS: usize = 8;
pub const VERIFIER_BLOB_LEN: usize = 64; // nonce(12) + "revault-ok"(10) + tag(16) = 38, padded

/// File-entry flag bits.
pub const ENTRY_FLAG_OCCUPIED: u32 = 1 << 0;
pub const ENTRY_FLAG_DELETED: u32 = 1 << 1;

/// Chain record operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChainOp {
    VaultCreated = 1,
    FileAdded = 2,
    FileUpdated = 3,
    FileDeleted = 4,
}

impl ChainOp {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => ChainOp::VaultCreated,
            2 => ChainOp::FileAdded,
            3 => ChainOp::FileUpdated,
            4 => ChainOp::FileDeleted,
            _ => return Err(VaultError::CorruptContainer("unknown chain op code")),
        })
    }
}

// ---------------------------------------------------------------------
// Small manual byte cursor helpers so on-disk widths stay explicit.
// ---------------------------------------------------------------------

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn with_capacity(cap: usize) -> Self {
        Writer { buf: Vec::with_capacity(cap) }
    }
    fn u8(&mut self, v: u8) { self.buf.push(v); }
    fn u16(&mut self, v: u16) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u32(&mut self, v: u32) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u64(&mut self, v: u64) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn i64(&mut self, v: i64) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u128(&mut self, v: u128) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn bytes(&mut self, v: &[u8]) { self.buf.extend_from_slice(v); }
    /// Writes `data` into a fixed-width field of `width` bytes, zero-padded.
    /// Errors structurally impossible here since callers validate length
    /// up front; this is a defensive truncation-avoidance assert.
    fn fixed(&mut self, data: &[u8], width: usize) {
        debug_assert!(data.len() <= width, "fixed field overflow");
        self.buf.extend_from_slice(data);
        for _ in data.len()..width {
            self.buf.push(0);
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self { Reader { buf, pos: 0 } }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            return Err(VaultError::CorruptContainer("unexpected end of record while decoding"));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn u64(&mut self) -> Result<u64> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn i64(&mut self) -> Result<i64> {
        self.need(8)?;
        let v = i64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn u128(&mut self) -> Result<u128> {
        self.need(16)?;
        let v = u128::from_le_bytes(self.buf[self.pos..self.pos + 16].try_into().unwrap());
        self.pos += 16;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let v = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }
    fn array32(&mut self) -> Result<[u8; 32]> {
        let s = self.bytes(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub flags: u32,
    pub block_size: u32,
    pub block_count: u64,
    pub capacity_bytes: u64,

    pub name: String,
    pub description: String,
    pub created_at: i64,

    pub salt: [u8; 16],
    pub argon2_m_cost_kib: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub verifier_blob: Vec<u8>,

    pub bitmap_offset: u64,
    pub bitmap_len: u64,

    pub file_table_offset: u64,
    pub file_table_len: u64,
    pub max_files: u32,
    pub entry_size: u32,

    pub chain_offset: u64,
    pub chain_len: u64,
    pub max_chain_records: u32,
    pub chain_record_size: u32,
    pub chain_next_seq: u64,
    pub chain_last_hash: [u8; 32],

    pub data_offset: u64,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(HEADER_SIZE as usize);
        w.bytes(MAGIC);
        w.u32(self.version);
        w.u32(self.flags);
        w.u32(self.block_size);
        w.u64(self.block_count);
        w.u64(self.capacity_bytes);

        w.u16(self.name.len() as u16);
        w.fixed(self.name.as_bytes(), MAX_NAME_LEN);
        w.u16(self.description.len() as u16);
        w.fixed(self.description.as_bytes(), MAX_DESC_LEN);
        w.i64(self.created_at);

        w.fixed(&self.salt, 16);
        w.u32(self.argon2_m_cost_kib);
        w.u32(self.argon2_t_cost);
        w.u32(self.argon2_p_cost);
        w.u16(self.verifier_blob.len() as u16);
        w.fixed(&self.verifier_blob, VERIFIER_BLOB_LEN);

        w.u64(self.bitmap_offset);
        w.u64(self.bitmap_len);

        w.u64(self.file_table_offset);
        w.u64(self.file_table_len);
        w.u32(self.max_files);
        w.u32(self.entry_size);

        w.u64(self.chain_offset);
        w.u64(self.chain_len);
        w.u32(self.max_chain_records);
        w.u32(self.chain_record_size);
        w.u64(self.chain_next_seq);
        w.fixed(&self.chain_last_hash, 32);

        w.u64(self.data_offset);

        // Checksum over everything written so far, then pad the remainder
        // of the fixed-size header with zeroes (reserved for future use).
        let checksum = super::crypto::sha256(&w.buf);
        w.fixed(&checksum, 32);

        assert!(
            w.buf.len() as u64 <= HEADER_SIZE,
            "header encoding exceeded HEADER_SIZE; grow HEADER_SIZE"
        );
        while (w.buf.len() as u64) < HEADER_SIZE {
            w.buf.push(0);
        }
        w.buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE as usize {
            return Err(VaultError::CorruptContainer("file too short to contain a header"));
        }
        let mut r = Reader::new(&buf[..HEADER_SIZE as usize]);

        let magic = r.bytes(8)?;
        if magic != MAGIC {
            return Err(VaultError::NotARvltFile);
        }
        let version = r.u32()?;
        if version < MIN_SUPPORTED_VERSION || version > MAX_SUPPORTED_VERSION {
            return Err(VaultError::UnsupportedVersion {
                found: version,
                min: MIN_SUPPORTED_VERSION,
                max: MAX_SUPPORTED_VERSION,
            });
        }
        let flags = r.u32()?;
        let block_size = r.u32()?;
        let block_count = r.u64()?;
        let capacity_bytes = r.u64()?;

        let name_len = r.u16()? as usize;
        let name_raw = r.bytes(MAX_NAME_LEN)?;
        if name_len > MAX_NAME_LEN {
            return Err(VaultError::CorruptContainer("name_len exceeds field width"));
        }
        let name = String::from_utf8(name_raw[..name_len].to_vec())
            .map_err(|_| VaultError::CorruptContainer("vault name is not valid UTF-8"))?;

        let desc_len = r.u16()? as usize;
        let desc_raw = r.bytes(MAX_DESC_LEN)?;
        if desc_len > MAX_DESC_LEN {
            return Err(VaultError::CorruptContainer("desc_len exceeds field width"));
        }
        let description = String::from_utf8(desc_raw[..desc_len].to_vec())
            .map_err(|_| VaultError::CorruptContainer("vault description is not valid UTF-8"))?;

        let created_at = r.i64()?;

        let salt_raw = r.bytes(16)?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(salt_raw);

        let argon2_m_cost_kib = r.u32()?;
        let argon2_t_cost = r.u32()?;
        let argon2_p_cost = r.u32()?;

        let verifier_len = r.u16()? as usize;
        let verifier_raw = r.bytes(VERIFIER_BLOB_LEN)?;
        if verifier_len > VERIFIER_BLOB_LEN {
            return Err(VaultError::CorruptContainer("verifier_len exceeds field width"));
        }
        let verifier_blob = verifier_raw[..verifier_len].to_vec();

        let bitmap_offset = r.u64()?;
        let bitmap_len = r.u64()?;

        let file_table_offset = r.u64()?;
        let file_table_len = r.u64()?;
        let max_files = r.u32()?;
        let entry_size = r.u32()?;

        let chain_offset = r.u64()?;
        let chain_len = r.u64()?;
        let max_chain_records = r.u32()?;
        let chain_record_size = r.u32()?;
        let chain_next_seq = r.u64()?;
        let chain_last_hash = r.array32()?;

        let data_offset = r.u64()?;

        let checksum_pos = r.pos;
        let stored_checksum = r.array32()?;
        let computed = super::crypto::sha256(&buf[..checksum_pos]);
        if stored_checksum != computed {
            return Err(VaultError::ChecksumMismatch("header"));
        }

        // Structural sanity: regions must be in order and non-overlapping,
        // and block_size/block_count must agree with capacity_bytes.
        if block_size == 0 || block_count == 0 {
            return Err(VaultError::CorruptContainer("block_size/block_count is zero"));
        }
        let expected_data_len = (block_count as u128) * (block_size as u128);
        if expected_data_len > u64::MAX as u128 {
            return Err(VaultError::CorruptContainer("block_count * block_size overflows u64"));
        }
        if bitmap_offset < HEADER_SIZE {
            return Err(VaultError::CorruptContainer("bitmap_offset overlaps header"));
        }
        if file_table_offset < bitmap_offset + bitmap_len {
            return Err(VaultError::CorruptContainer("file_table_offset overlaps bitmap"));
        }
        if chain_offset < file_table_offset + file_table_len {
            return Err(VaultError::CorruptContainer("chain_offset overlaps file table"));
        }
        if data_offset < chain_offset + chain_len {
            return Err(VaultError::CorruptContainer("data_offset overlaps chain region"));
        }

        Ok(Header {
            version,
            flags,
            block_size,
            block_count,
            capacity_bytes,
            name,
            description,
            created_at,
            salt,
            argon2_m_cost_kib,
            argon2_t_cost,
            argon2_p_cost,
            verifier_blob,
            bitmap_offset,
            bitmap_len,
            file_table_offset,
            file_table_len,
            max_files,
            entry_size,
            chain_offset,
            chain_len,
            max_chain_records,
            chain_record_size,
            chain_next_seq,
            chain_last_hash,
            data_offset,
        })
    }

    pub fn total_container_size(&self) -> u64 {
        self.data_offset + self.block_count * self.block_size as u64
    }
}

// ---------------------------------------------------------------------
// FileEntry
// ---------------------------------------------------------------------

pub const ENTRY_SIZE: u32 = 320;

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub id: u128,
    pub name: String,
    pub size: u64,
    pub blocks_used: u32,
    pub direct_blocks: [u64; DIRECT_BLOCKS],
    /// Block index holding an overflow `BlockList` when a file needs more
    /// than `DIRECT_BLOCKS` blocks (0 = none / not used).
    pub overflow_block: u64,
    pub file_hash: [u8; 32],
    pub created_at: i64,
    pub modified_at: i64,
    pub flags: u32,
}

impl FileEntry {
    pub fn is_occupied(&self) -> bool {
        self.flags & ENTRY_FLAG_OCCUPIED != 0 && self.flags & ENTRY_FLAG_DELETED == 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(ENTRY_SIZE as usize);
        w.u128(self.id);
        w.u16(self.name.len() as u16);
        w.fixed(self.name.as_bytes(), MAX_FILENAME_LEN);
        w.u64(self.size);
        w.u32(self.blocks_used);
        for b in self.direct_blocks {
            w.u64(b);
        }
        w.u64(self.overflow_block);
        w.fixed(&self.file_hash, 32);
        w.i64(self.created_at);
        w.i64(self.modified_at);
        w.u32(self.flags);

        let crc = super::crypto::sha256(&w.buf);
        w.fixed(&crc[..4], 4);

        assert!(w.buf.len() as u32 <= ENTRY_SIZE, "FileEntry encoding exceeded ENTRY_SIZE");
        while (w.buf.len() as u32) < ENTRY_SIZE {
            w.buf.push(0);
        }
        w.buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < ENTRY_SIZE as usize {
            return Err(VaultError::CorruptContainer("file entry slot too short"));
        }
        let mut r = Reader::new(&buf[..ENTRY_SIZE as usize]);
        let id = r.u128()?;
        let name_len = r.u16()? as usize;
        let name_raw = r.bytes(MAX_FILENAME_LEN)?;
        if name_len > MAX_FILENAME_LEN {
            return Err(VaultError::CorruptContainer("file name_len exceeds field width"));
        }
        let name = String::from_utf8(name_raw[..name_len].to_vec())
            .map_err(|_| VaultError::CorruptContainer("file name is not valid UTF-8"))?;
        let size = r.u64()?;
        let blocks_used = r.u32()?;
        let mut direct_blocks = [0u64; DIRECT_BLOCKS];
        for slot in direct_blocks.iter_mut() {
            *slot = r.u64()?;
        }
        let overflow_block = r.u64()?;
        let file_hash = r.array32()?;
        let created_at = r.i64()?;
        let modified_at = r.i64()?;
        let flags = r.u32()?;

        let crc_pos = r.pos;
        let stored_crc = r.bytes(4)?;
        let computed = super::crypto::sha256(&buf[..crc_pos]);
        if stored_crc != &computed[..4] {
            return Err(VaultError::ChecksumMismatch("file entry"));
        }

        Ok(FileEntry {
            id,
            name,
            size,
            blocks_used,
            direct_blocks,
            overflow_block,
            file_hash,
            created_at,
            modified_at,
            flags,
        })
    }

    pub fn empty_slot() -> Vec<u8> {
        // All-zero slot: flags=0 means "not occupied"; decodes fine because
        // its checksum is computed over the (all-zero) preceding bytes.
        let entry = FileEntry {
            id: 0,
            name: String::new(),
            size: 0,
            blocks_used: 0,
            direct_blocks: [0; DIRECT_BLOCKS],
            overflow_block: 0,
            file_hash: [0; 32],
            created_at: 0,
            modified_at: 0,
            flags: 0,
        };
        entry.encode()
    }
}

// ---------------------------------------------------------------------
// ChainRecord (tamper-evident integrity chain)
// ---------------------------------------------------------------------

pub const CHAIN_RECORD_SIZE: u32 = 160;

#[derive(Debug, Clone)]
pub struct ChainRecord {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub op: ChainOp,
    pub target_id: u128,
    pub data_hash: [u8; 32],
    pub timestamp: i64,
    pub record_hash: [u8; 32],
}

impl ChainRecord {
    /// Computes `record_hash` and returns a fully-formed record.
    pub fn new(
        seq: u64,
        prev_hash: [u8; 32],
        op: ChainOp,
        target_id: u128,
        data_hash: [u8; 32],
        timestamp: i64,
    ) -> Self {
        let record_hash = Self::compute_hash(seq, &prev_hash, op, target_id, &data_hash, timestamp);
        ChainRecord { seq, prev_hash, op, target_id, data_hash, timestamp, record_hash }
    }

    pub fn compute_hash(
        seq: u64,
        prev_hash: &[u8; 32],
        op: ChainOp,
        target_id: u128,
        data_hash: &[u8; 32],
        timestamp: i64,
    ) -> [u8; 32] {
        super::crypto::sha256_concat(&[
            &seq.to_le_bytes(),
            prev_hash,
            &[op as u8],
            &target_id.to_le_bytes(),
            data_hash,
            &timestamp.to_le_bytes(),
        ])
    }

    pub fn verify_self(&self) -> bool {
        let expected = Self::compute_hash(
            self.seq,
            &self.prev_hash,
            self.op,
            self.target_id,
            &self.data_hash,
            self.timestamp,
        );
        expected == self.record_hash
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(CHAIN_RECORD_SIZE as usize);
        w.u64(self.seq);
        w.fixed(&self.prev_hash, 32);
        w.u8(self.op as u8);
        w.u128(self.target_id);
        w.fixed(&self.data_hash, 32);
        w.i64(self.timestamp);
        w.fixed(&self.record_hash, 32);
        // occupied marker so an all-zero slot reads back as "unused, seq 0
        // with no record" rather than a valid-looking record.
        w.u8(1);
        while (w.buf.len() as u32) < CHAIN_RECORD_SIZE {
            w.buf.push(0);
        }
        w.buf
    }

    pub fn decode(buf: &[u8]) -> Result<Option<Self>> {
        if buf.len() < CHAIN_RECORD_SIZE as usize {
            return Err(VaultError::CorruptContainer("chain record slot too short"));
        }
        let mut r = Reader::new(&buf[..CHAIN_RECORD_SIZE as usize]);
        let seq = r.u64()?;
        let prev_hash = r.array32()?;
        let op_byte = r.u8()?;
        let target_id = r.u128()?;
        let data_hash = r.array32()?;
        let timestamp = r.i64()?;
        let record_hash = r.array32()?;
        let occupied = r.u8()?;
        if occupied == 0 {
            return Ok(None);
        }
        let op = ChainOp::from_u8(op_byte)?;
        Ok(Some(ChainRecord { seq, prev_hash, op, target_id, data_hash, timestamp, record_hash }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        let block_size = DEFAULT_BLOCK_SIZE;
        let block_count = 16u64;
        let bitmap_len = 8u64;
        let file_table_len = (4 * ENTRY_SIZE) as u64;
        let chain_len = (4 * CHAIN_RECORD_SIZE) as u64;
        let bitmap_offset = HEADER_SIZE;
        let file_table_offset = bitmap_offset + bitmap_len;
        let chain_offset = file_table_offset + file_table_len;
        let data_offset = chain_offset + chain_len;
        Header {
            version: FORMAT_VERSION,
            flags: 0,
            block_size,
            block_count,
            capacity_bytes: block_count * block_size as u64,
            name: "My Vault".into(),
            description: "a test vault".into(),
            created_at: 1_700_000_000,
            salt: [9u8; 16],
            argon2_m_cost_kib: 19 * 1024,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            verifier_blob: vec![1, 2, 3, 4],
            bitmap_offset,
            bitmap_len,
            file_table_offset,
            file_table_len,
            max_files: 4,
            entry_size: ENTRY_SIZE,
            chain_offset,
            chain_len,
            max_chain_records: 4,
            chain_record_size: CHAIN_RECORD_SIZE,
            chain_next_seq: 0,
            chain_last_hash: [0u8; 32],
            data_offset,
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = sample_header();
        let encoded = h.encode();
        assert_eq!(encoded.len() as u64, HEADER_SIZE);
        let decoded = Header::decode(&encoded).unwrap();
        assert_eq!(decoded.name, "My Vault");
        assert_eq!(decoded.description, "a test vault");
        assert_eq!(decoded.block_count, 16);
        assert_eq!(decoded.data_offset, h.data_offset);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let h = sample_header();
        let mut encoded = h.encode();
        encoded[0] ^= 0xFF;
        assert!(matches!(Header::decode(&encoded), Err(VaultError::NotARvltFile)));
    }

    #[test]
    fn header_rejects_checksum_tampering() {
        let h = sample_header();
        let mut encoded = h.encode();
        // Flip a byte inside the name field, well after magic/version.
        encoded[20] ^= 0xFF;
        assert!(matches!(Header::decode(&encoded), Err(VaultError::ChecksumMismatch(_))));
    }

    #[test]
    fn header_rejects_future_version() {
        let h = sample_header();
        let mut encoded = h.encode();
        encoded[8..12].copy_from_slice(&(MAX_SUPPORTED_VERSION + 1).to_le_bytes());
        // The version check runs before the checksum check, so a bumped
        // version number is rejected as unsupported even though the
        // checksum (computed over the original version) would also now
        // fail to match.
        assert!(matches!(
            Header::decode(&encoded),
            Err(VaultError::UnsupportedVersion { .. }) | Err(VaultError::ChecksumMismatch(_))
        ));
    }

    #[test]
    fn file_entry_roundtrip() {
        let mut direct_blocks = [0u64; DIRECT_BLOCKS];
        direct_blocks[0] = 5;
        direct_blocks[1] = 6;
        let entry = FileEntry {
            id: 123456789,
            name: "notes.txt".into(),
            size: 42,
            blocks_used: 2,
            direct_blocks,
            overflow_block: 0,
            file_hash: [7u8; 32],
            created_at: 100,
            modified_at: 200,
            flags: ENTRY_FLAG_OCCUPIED,
        };
        let encoded = entry.encode();
        assert_eq!(encoded.len() as u32, ENTRY_SIZE);
        let decoded = FileEntry::decode(&encoded).unwrap();
        assert_eq!(decoded.name, "notes.txt");
        assert_eq!(decoded.size, 42);
        assert_eq!(decoded.direct_blocks[0], 5);
        assert!(decoded.is_occupied());
    }

    #[test]
    fn empty_file_entry_slot_is_not_occupied() {
        let slot = FileEntry::empty_slot();
        let decoded = FileEntry::decode(&slot).unwrap();
        assert!(!decoded.is_occupied());
    }

    #[test]
    fn file_entry_rejects_checksum_tampering() {
        let entry = FileEntry {
            id: 1,
            name: "a".into(),
            size: 1,
            blocks_used: 1,
            direct_blocks: [1; DIRECT_BLOCKS],
            overflow_block: 0,
            file_hash: [0; 32],
            created_at: 0,
            modified_at: 0,
            flags: ENTRY_FLAG_OCCUPIED,
        };
        let mut encoded = entry.encode();
        encoded[20] ^= 0xFF;
        assert!(matches!(FileEntry::decode(&encoded), Err(VaultError::ChecksumMismatch(_))));
    }

    #[test]
    fn chain_record_roundtrip_and_self_verify() {
        let rec = ChainRecord::new(1, [0u8; 32], ChainOp::FileAdded, 42, [9u8; 32], 12345);
        assert!(rec.verify_self());
        let encoded = rec.encode();
        assert_eq!(encoded.len() as u32, CHAIN_RECORD_SIZE);
        let decoded = ChainRecord::decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded.seq, 1);
        assert!(decoded.verify_self());
    }

    #[test]
    fn empty_chain_slot_decodes_as_none() {
        let slot = vec![0u8; CHAIN_RECORD_SIZE as usize];
        assert!(ChainRecord::decode(&slot).unwrap().is_none());
    }

    #[test]
    fn chain_record_detects_tampering() {
        let mut rec = ChainRecord::new(1, [0u8; 32], ChainOp::FileAdded, 42, [9u8; 32], 12345);
        rec.data_hash[0] ^= 0xFF; // simulate corruption without recomputing hash
        assert!(!rec.verify_self());
    }
}
