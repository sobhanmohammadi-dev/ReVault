//! High-level sync operations built on the encrypted channel: an admin
//! serving a join/catch-up request, and a peer joining or receiving a
//! live push.
//!
//! # Catch-up: incremental when possible, full resync otherwise
//!
//! `Vault::take_change_log` only captures byte ranges written by the
//! *most recent* mutating call -- on its own that's only enough for a
//! live push to already-connected peers. [`PatchJournal`] extends that
//! into a small bounded history so a peer reconnecting after missing a
//! few changes can still get an incremental patch (see that module's
//! docs for why it's in-memory only, not persisted to disk). When the
//! journal doesn't have unbroken coverage back to where the peer claims
//! to be -- including a brand-new peer with `next_seq == 0`, or simply
//! no journal at all -- `serve_one` falls back to a full `export_full()`
//! copy. That fallback is always correct, just not maximally efficient.

use std::net::SocketAddr;
use std::path::Path;

use tokio::net::{TcpListener, TcpStream};

use crate::core::error::{Result, VaultError};
use crate::core::identity::{Identity, PeerId};
use crate::core::Vault;

use super::handshake::SecureChannel;
use super::journal::PatchJournal;
use super::protocol::SyncMessage;

/// Admin side, lower-level primitive: serves one already-accepted
/// connection. Split out from [`serve_one`] so a caller that needs to
/// interleave accepting connections with something else (e.g. reading
/// admin commands from stdin, via `tokio::select!`) can do so without
/// this function owning the whole accept loop.
pub async fn serve_stream(
    stream: TcpStream,
    my_identity: &Identity,
    vault: &mut Vault,
    journal: Option<&PatchJournal>,
) -> Result<PeerId> {
    let (mut channel, their_peer_id) = SecureChannel::responder(stream, my_identity).await?;

    let granted = vault.list_recipients()?.into_iter().any(|r| r.peer_id == their_peer_id);
    if !granted {
        let _ = channel.send(&SyncMessage::Error { message: "not granted access to this vault".to_string() }.encode()).await;
        return Err(VaultError::NotAuthorized);
    }

    let their_state_bytes = channel.recv().await?;
    match SyncMessage::decode(&their_state_bytes)? {
        SyncMessage::ChainState { next_seq, .. } => {
            let patch = journal.and_then(|j| j.ranges_since(next_seq));
            match patch {
                Some(ranges) => {
                    channel.send(&SyncMessage::Patch { seq: next_seq, ranges }.encode()).await?;
                }
                None => {
                    // No journal, or the peer is further behind than its
                    // retained window -- always correct, just not the
                    // most efficient path (see `journal` module docs).
                    let bytes = vault.export_full()?;
                    channel.send(&SyncMessage::FullSync { bytes }.encode()).await?;
                }
            }
        }
        _ => {
            let _ = channel.send(&SyncMessage::Error { message: "expected a ChainState message".to_string() }.encode()).await;
            return Err(VaultError::CorruptContainer("peer did not send ChainState first"));
        }
    }

    Ok(their_peer_id)
}

/// Convenience wrapper around [`serve_stream`] for callers that don't
/// need to interleave accepting with anything else: accepts exactly one
/// connection from `listener` and serves it.
pub async fn serve_one(
    listener: &TcpListener,
    my_identity: &Identity,
    vault: &mut Vault,
    journal: Option<&PatchJournal>,
) -> Result<PeerId> {
    let (stream, _addr) = listener.accept().await.map_err(VaultError::Io)?;
    serve_stream(stream, my_identity, vault, journal).await
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
            serve_one(&listener, &listener_identity, &mut vault, None).await.unwrap();
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

        let server_task = tokio::spawn(async move { serve_one(&listener, &listener_identity, &mut vault, None).await });

        let result = join(addr, &stranger, &expected_listener_peer, &peer_path).await;
        assert!(result.is_err());

        let server_result = server_task.await.unwrap();
        assert!(matches!(server_result, Err(VaultError::NotAuthorized)));
    }

    #[tokio::test]
    async fn reconnecting_peer_gets_an_incremental_patch_when_journal_covers_it() {
        let dir = tempdir().unwrap();
        let admin_path = dir.path().join("admin.rvlt");
        let peer_path = dir.path().join("peer-replica.rvlt");

        let mut vault = Vault::create(&admin_path, "V", "d", 256 * 1024, "pw", Identity::generate()).unwrap();
        let peer_identity = Identity::generate();
        vault.grant_access(&peer_identity.peer_id()).unwrap();
        let _ = vault.take_change_log(); // not relevant to what this test checks

        let listener_identity_bytes = Identity::generate().to_bytes();
        let expected_listener_peer = Identity::from_bytes(&listener_identity_bytes).peer_id();
        let mut journal = PatchJournal::new(8);

        // Peer joins for the first time -- always a full sync, and
        // establishes what "caught up" (next_seq_before) means for them.
        let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let (server_result, join_result) = tokio::join!(
            serve_one(&listener1, &Identity::from_bytes(&listener_identity_bytes), &mut vault, Some(&journal)),
            join(addr1, &peer_identity, &expected_listener_peer, &peer_path)
        );
        server_result.unwrap();
        drop(join_result.unwrap());
        let (next_seq_before, _) = vault.chain_state();

        // Admin adds a file and records the resulting patch in the journal.
        vault.add_file("new.txt", b"added after the peer joined").unwrap();
        journal.record(next_seq_before, vault.take_change_log());

        // Peer reconnects claiming next_seq_before -- the journal covers
        // exactly that, so it should get a Patch, not another FullSync.
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let client_fut = async {
            let stream = tokio::net::TcpStream::connect(addr2).await.unwrap();
            let (mut channel, _admin_peer) =
                SecureChannel::initiator(stream, &peer_identity, &expected_listener_peer).await.unwrap();
            channel
                .send(&SyncMessage::ChainState { next_seq: next_seq_before, last_hash: [0u8; 32] }.encode())
                .await
                .unwrap();
            let response = channel.recv().await.unwrap();
            SyncMessage::decode(&response).unwrap()
        };
        let (server_result, message) = tokio::join!(
            serve_one(&listener2, &Identity::from_bytes(&listener_identity_bytes), &mut vault, Some(&journal)),
            client_fut
        );
        server_result.unwrap();
        match message {
            SyncMessage::Patch { .. } => {} // expected: incremental, not a full resync
            other => panic!("expected a Patch, got {other:?}"),
        }
    }
}
