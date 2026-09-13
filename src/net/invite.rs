//! Shareable "invite" strings: a `PeerId` plus an optional address to
//! dial, encoded as hex text so it's easy to paste into a terminal
//! prompt or a chat message.
//!
//! Hex rather than base64 on purpose: no extra crate dependency for
//! something this simple, at the cost of the string being a bit longer.

use std::net::SocketAddr;

use crate::core::error::{Result, VaultError};
use crate::core::identity::PeerId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCode {
    pub peer_id: PeerId,
    pub address: Option<SocketAddr>,
}

impl InviteCode {
    pub fn encode(&self) -> String {
        let mut bytes = self.peer_id.to_bytes().to_vec();
        match self.address {
            Some(addr) => {
                bytes.push(1);
                bytes.extend_from_slice(addr.to_string().as_bytes());
            }
            None => bytes.push(0),
        }
        hex_encode(&bytes)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = hex_decode(s.trim())?;
        if bytes.len() < 65 {
            return Err(VaultError::CorruptContainer("invite code is too short"));
        }
        let peer_id = PeerId::from_bytes(&bytes[..64])?;
        let has_addr = bytes[64];
        let address = match has_addr {
            0 => None,
            1 => {
                let addr_str = std::str::from_utf8(&bytes[65..])
                    .map_err(|_| VaultError::CorruptContainer("invite code address is not valid UTF-8"))?;
                let addr = addr_str
                    .parse::<SocketAddr>()
                    .map_err(|_| VaultError::CorruptContainer("invite code has an invalid address"))?;
                Some(addr)
            }
            _ => return Err(VaultError::CorruptContainer("invite code has an invalid address marker")),
        };
        Ok(InviteCode { peer_id, address })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(VaultError::CorruptContainer("invite code has odd length"));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(VaultError::CorruptContainer("invite code contains a non-hex character")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::Identity;

    #[test]
    fn roundtrip_without_address() {
        let peer_id = Identity::generate().peer_id();
        let invite = InviteCode { peer_id, address: None };
        let decoded = InviteCode::decode(&invite.encode()).unwrap();
        assert_eq!(decoded, invite);
    }

    #[test]
    fn roundtrip_with_address() {
        let peer_id = Identity::generate().peer_id();
        let invite = InviteCode { peer_id, address: Some("127.0.0.1:9000".parse().unwrap()) };
        let decoded = InviteCode::decode(&invite.encode()).unwrap();
        assert_eq!(decoded, invite);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(InviteCode::decode("not hex at all").is_err());
        assert!(InviteCode::decode("abc").is_err()); // odd length
        assert!(InviteCode::decode("00").is_err()); // too short
    }

    #[test]
    fn encode_is_pure_hex_lowercase() {
        let peer_id = Identity::generate().peer_id();
        let invite = InviteCode { peer_id, address: None };
        let encoded = invite.encode();
        assert!(encoded.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
