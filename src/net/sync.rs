//! High-level sync operations built on the encrypted channel: an admin
//! serving a join/catch-up request, and a peer joining or receiving a
//! live push.
//!
//! # Why catch-up always does a full resync (v1 limitation)
//!
//! `Vault::take_change_log` only captures byte ranges written by the
//! *most recent* mutating call in this process -- there's no persistent,
//! seq-indexed history of past patches kept anywhere. That's enough for
//! a "live push": the admin makes a change and immediately forwards that
//! change_log to whichever peers are currently connected. It is *not*
//! enough to reconstruct what changed for a peer that reconnects after
//! being offline for a while, since by then the relevant change_log
//! entries are long gone. Rather than get that wrong, a peer who is
//! behind (including a brand-new peer with `next_seq == 0`) always gets
//! a full `export_full()` copy. This is correct in every case, just not
//! maximally efficient for a peer that missed only one or two changes --
//! a documented place to improve on later (e.g. by having the admin keep
//! a bounded on-disk journal of recent patches, mirroring the chain's
//! own bounded-window design).

use std::net::SocketAddr;
use std::path::Path;

use tokio::net::{TcpListener, TcpStream};

use crate::core::error::{Result, VaultError};
use crate::core::identity::{Identity, PeerId};
use crate::core::Vault;

use super::handshake::SecureChannel;
use super::protocol::SyncMessage;

/// Admin side: accepts one incoming connection, verifies the caller is a
/// granted recipient of `vault`, and brings them fully up to date.
/// Returns the connecting peer's identity on success.
pub async fn serve_one(listener: &TcpListener, my_identity: &Identity, vault: &mut Vault) -> Result<PeerId> {
    let (stream, _addr) = listener.accept().await.map_err(VaultError::Io)?;
    let (mut channel, their_peer_id) = SecureChannel::responder(stream, my_identity).await?;

    let granted = vault.list_recipients()?.into_iter().any(|r| r.peer_id == their_peer_id);
    if !granted {
        let _ = channel.send(&SyncMessage::Error { message: "not granted access to this vault".to_string() }.encode()).await;
        return Err(VaultError::NotAuthorized);
    }

    let their_state_bytes = channel.recv().await?;
    match SyncMessage::decode(&their_state_bytes)? {
        SyncMessage::ChainState { .. } => {
            // See module docs: every catch-up, regardless of how far
            // behind the peer claims to be, gets a full resync in v1.
            let bytes = vault.export_full()?;
            channel.send(&SyncMessage::FullSync { bytes }.encode()).await?;
        }
        _ => {
            let _ = channel.send(&SyncMessage::Error { message: "expected a ChainState message".to_string() }.encode()).await;
            return Err(VaultError::CorruptContainer("peer did not send ChainState first"));
        }
    }

    Ok(their_peer_id)
}

/// Peer side: connects to `addr`, verifies the responder is really
/// `expected_admin` (pinned from an invite code, not discovered), and
/// requests a full sync. Writes the result to `local_path` and returns
/// an opened `Vault` handle for it.
pub async fn join(
    addr: SocketAddr,
    my_identity: &Identity,
    expected_admin: &PeerId,
    local_path: &Path,
) -> Result<Vault> {
    let stream = TcpStream::connect(addr).await.map_err(VaultError::Io)?;
    let (mut channel, _admin_peer_id) = SecureChannel::initiator(stream, my_identity, expected_admin).await?;

    channel.send(&SyncMessage::ChainState { next_seq: 0, last_hash: [0u8; 32] }.encode()).await?;
    let response_bytes = channel.recv().await?;
    match SyncMessage::decode(&response_bytes)? {
        SyncMessage::FullSync { bytes } => {
            std::fs::write(local_path, bytes).map_err(VaultError::Io)?;
            Vault::open_as_recipient(local_path, my_identity)
        }
        SyncMessage::Error { message } => Err(VaultError::Remote(message)),
        _ => Err(VaultError::CorruptContainer("unexpected response while joining")),
    }
}

/// Admin side, live push: sends a change-log patch to an already
/// connected, already-authenticated peer channel. Call this right after
/// a mutating `Vault` call, with whatever `take_change_log()` returned.
pub async fn push_patch(channel: &mut SecureChannel<TcpStream>, seq: u64, ranges: Vec<(u64, Vec<u8>)>) -> Result<()> {
    channel.send(&SyncMessage::Patch { seq, ranges }.encode()).await
}

/// Peer side, live push: reads one incoming message on an established
/// channel and applies it if it's a patch.
pub async fn apply_incoming(channel: &mut SecureChannel<TcpStream>, vault: &mut Vault) -> Result<()> {
    let bytes = channel.recv().await?;
    match SyncMessage::decode(&bytes)? {
        SyncMessage::Patch { ranges, .. } => vault.apply_remote_patch(&ranges),
        SyncMessage::UpToDate => Ok(()),
        SyncMessage::Error { message } => Err(VaultError::Remote(message)),
        _ => Err(VaultError::CorruptContainer("unexpected message while applying incoming sync")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn peer_can_join_and_read_granted_content() {
        let dir = tempdir().unwrap();
        let admin_path = dir.path().join("admin.rvlt");
        let peer_path = dir.path().join("peer-replica.rvlt");

        let mut vault = Vault::create(&admin_path, "V", "d", 256 * 1024, "pw", Identity::generate()).unwrap();
        vault.add_file("hello.txt", b"shared over the wire").unwrap();

        let peer_identity = Identity::generate();
        vault.grant_access(&peer_identity.peer_id()).unwrap();

        // The listener's own network identity only needs to be *some*
        // identity the connecting peer can pin via an invite code --
        // authorization is checked against the vault's recipient list by
        // the connecting peer's identity, not the listener's.
        let listener_identity = Identity::generate();
        let expected_listener_peer = listener_identity.peer_id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            serve_one(&listener, &listener_identity, &mut vault).await.unwrap();
        });

        let mut joined_vault = join(addr, &peer_identity, &expected_listener_peer, &peer_path).await.unwrap();
        assert_eq!(joined_vault.read_file("hello.txt").unwrap(), b"shared over the wire");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn ungranted_peer_is_rejected() {
        let dir = tempdir().unwrap();
        let admin_path = dir.path().join("admin.rvlt");
        let peer_path = dir.path().join("peer-replica.rvlt");

        let mut vault = Vault::create(&admin_path, "V", "d", 256 * 1024, "pw", Identity::generate()).unwrap();
        vault.add_file("hello.txt", b"secret").unwrap();

        let stranger = Identity::generate();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let listener_identity = Identity::generate();
        let expected_listener_peer = listener_identity.peer_id();

        let server_task = tokio::spawn(async move { serve_one(&listener, &listener_identity, &mut vault).await });

        let result = join(addr, &stranger, &expected_listener_peer, &peer_path).await;
        assert!(result.is_err());

        let server_result = server_task.await.unwrap();
        assert!(matches!(server_result, Err(VaultError::NotAuthorized)));
    }
}
