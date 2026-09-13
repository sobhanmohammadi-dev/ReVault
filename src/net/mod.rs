//! Peer-to-peer networking.
//!
//! v1, per `docs/ARCHITECTURE_NETWORK.md`: no discovery yet (dial a known
//! `ip:port` from an invite code), a from-scratch authenticated+encrypted
//! channel (not a formally analyzed protocol -- see `handshake` module
//! docs), and a sync protocol that ships either a full vault copy (join /
//! catch-up) or an incremental byte-range patch (live push while
//! connected).
//!
//! Not implemented here: peer discovery (DHT/gossip), NAT traversal, and
//! any TUI for managing connections -- those are the next phases.

pub mod handshake;
pub mod invite;
pub mod protocol;
pub mod sync;

pub use handshake::SecureChannel;
pub use invite::InviteCode;
pub use protocol::SyncMessage;
