//! Wire framing and the sync message types exchanged between peers after
//! the handshake.
//!
//! Hand-rolled binary encoding (explicit widths, no serde-on-the-wire) to
//! stay consistent with the rest of the codebase and avoid a dependency
//! whose exact derive behavior can't be verified without a compiler in
//! this environment.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::error::{Result, VaultError};

/// Caps how large a single frame is allowed to claim to be, so a
/// malicious or broken peer can't make us allocate an enormous buffer
/// just by sending a bogus length prefix.
pub const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024; // 64 MiB

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame exceeds maximum size"));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> std::io::Result<()> {
    if data.len() as u64 > MAX_FRAME_LEN as u64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame exceeds maximum size"));
    }
    writer.write_all(&(data.len() as u32).to_le_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Application-level sync messages, exchanged once the encrypted channel
/// is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncMessage {
    /// "Here's where my chain is" -- sent by a joining/reconnecting peer
    /// so the admin knows what to send back. `next_seq == 0` means "I
    /// have no local replica at all, send me everything."
    ChainState { next_seq: u64, last_hash: [u8; 32] },
    /// A byte-range patch produced by `Vault::take_change_log`, tagged
    /// with the chain seq it corresponds to (informational only -- the
    /// ranges are applied in the order given regardless).
    Patch { seq: u64, ranges: Vec<(u64, Vec<u8>)> },
    /// The admin's full current container. Used both for a brand-new
    /// peer's initial join and, in this version, for any catch-up sync
    /// (see `net::sync` docs on why the simpler full-resync path is used
    /// there rather than reconstructing history from an arbitrary seq).
    FullSync { bytes: Vec<u8> },
    /// Explicit "nothing more to send right now."
    UpToDate,
    Error { message: String },
}

impl SyncMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            SyncMessage::ChainState { next_seq, last_hash } => {
                buf.push(1);
                buf.extend_from_slice(&next_seq.to_le_bytes());
                buf.extend_from_slice(last_hash);
            }
            SyncMessage::Patch { seq, ranges } => {
                buf.push(2);
                buf.extend_from_slice(&seq.to_le_bytes());
                buf.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
                for (offset, data) in ranges {
                    buf.extend_from_slice(&offset.to_le_bytes());
                    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    buf.extend_from_slice(data);
                }
            }
            SyncMessage::FullSync { bytes } => {
                buf.push(3);
                buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            SyncMessage::UpToDate => buf.push(4),
            SyncMessage::Error { message } => {
                buf.push(5);
                let msg_bytes = message.as_bytes();
                buf.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(msg_bytes);
            }
        }
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        fn need(buf: &[u8], pos: usize, n: usize) -> Result<()> {
            match pos.checked_add(n) {
                Some(end) if end <= buf.len() => Ok(()),
                _ => Err(VaultError::CorruptContainer("truncated sync message")),
            }
        }

        if buf.is_empty() {
            return Err(VaultError::CorruptContainer("empty sync message"));
        }
        let mut pos = 1usize;
        match buf[0] {
            1 => {
                need(buf, pos, 8 + 32)?;
                let next_seq = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let mut last_hash = [0u8; 32];
                last_hash.copy_from_slice(&buf[pos..pos + 32]);
                Ok(SyncMessage::ChainState { next_seq, last_hash })
            }
            2 => {
                need(buf, pos, 8 + 4)?;
                let seq = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let count = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                let mut ranges = Vec::with_capacity(count);
                for _ in 0..count {
                    need(buf, pos, 8 + 4)?;
                    let offset = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                    pos += 4;
                    need(buf, pos, len)?;
                    let data = buf[pos..pos + len].to_vec();
                    pos += len;
                    ranges.push((offset, data));
                }
                Ok(SyncMessage::Patch { seq, ranges })
            }
            3 => {
                need(buf, pos, 8)?;
                let len = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()) as usize;
                pos += 8;
                need(buf, pos, len)?;
                Ok(SyncMessage::FullSync { bytes: buf[pos..pos + len].to_vec() })
            }
            4 => Ok(SyncMessage::UpToDate),
            5 => {
                need(buf, pos, 4)?;
                let len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                need(buf, pos, len)?;
                let message = String::from_utf8_lossy(&buf[pos..pos + len]).to_string();
                Ok(SyncMessage::Error { message })
            }
            _ => Err(VaultError::CorruptContainer("unknown sync message tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_state_roundtrip() {
        let msg = SyncMessage::ChainState { next_seq: 42, last_hash: [7u8; 32] };
        let decoded = SyncMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn patch_roundtrip_with_multiple_ranges() {
        let msg = SyncMessage::Patch {
            seq: 3,
            ranges: vec![(0, vec![1, 2, 3]), (4096, vec![9u8; 100]), (8192, Vec::new())],
        };
        let decoded = SyncMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn full_sync_roundtrip() {
        let msg = SyncMessage::FullSync { bytes: vec![1, 2, 3, 4, 5] };
        let decoded = SyncMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn up_to_date_roundtrip() {
        let msg = SyncMessage::UpToDate;
        let decoded = SyncMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn error_roundtrip() {
        let msg = SyncMessage::Error { message: "no access".to_string() };
        let decoded = SyncMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_rejects_empty_and_truncated_input() {
        assert!(SyncMessage::decode(&[]).is_err());
        assert!(SyncMessage::decode(&[1, 2, 3]).is_err()); // tag 1 needs 40 more bytes
        assert!(SyncMessage::decode(&[99]).is_err()); // unknown tag
    }
}
