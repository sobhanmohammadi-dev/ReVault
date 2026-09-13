//! CLI entry points for the network feature: sharing your identity,
//! granting/revoking peer access, serving a vault to granted peers, and
//! joining a vault as a granted peer.
//!
//! These wrap the async `revault::net` API in a one-off Tokio runtime
//! per invocation, since the rest of the CLI/TUI is synchronous.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::core::{Identity, Vault};
use crate::net::{sync, InviteCode};

pub struct Whoami;

impl Whoami {
    /// Prints this device's shareable invite code. Pass `listen` if this
    /// device intends to run `serve` so the invite embeds an address a
    /// peer can dial directly; otherwise the invite carries identity only
    /// and the address must be arranged some other way.
    pub fn execute(listen: Option<SocketAddr>) -> std::io::Result<()> {
        let identity = Identity::load_or_create()?;
        let invite = InviteCode { peer_id: identity.peer_id(), address: listen };
        println!("Your identity fingerprint: {}", identity.peer_id().fingerprint());
        println!("Invite code (share this with whoever should grant you access,");
        println!("or with a peer you're about to grant access to):");
        println!("{}", invite.encode());
        Ok(())
    }
}

pub struct Grant;

impl Grant {
    pub fn execute(vault: PathBuf, password: String, peer_invite: String) -> std::io::Result<()> {
        let invite = InviteCode::decode(&peer_invite).map_err(to_io_err)?;
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        v.grant_access(&invite.peer_id).map_err(to_io_err)?;
        println!("Granted access to {}", invite.peer_id.fingerprint());
        Ok(())
    }
}

pub struct Revoke;

impl Revoke {
    pub fn execute(vault: PathBuf, password: String, peer_invite: String) -> std::io::Result<()> {
        let invite = InviteCode::decode(&peer_invite).map_err(to_io_err)?;
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        v.revoke_access(&invite.peer_id.signing_public, &password).map_err(to_io_err)?;
        println!(
            "Revoked access from {} and rotated the vault's encryption key.",
            invite.peer_id.fingerprint()
        );
        Ok(())
    }
}

pub struct Serve;

impl Serve {
    pub fn execute(vault: PathBuf, password: String, listen: SocketAddr) -> std::io::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async move {
            let local_identity = Identity::load_or_create()?;
            let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;

            let listener = tokio::net::TcpListener::bind(listen).await?;
            println!("Serving on {listen}. Waiting for granted peers to connect (Ctrl+C to stop)...");

            // Each accepted connection gets its own long-lived identity
            // for the handshake -- reuse the same local identity file
            // every time, loaded fresh per connection to keep this loop
            // simple and avoid holding a borrow across iterations.
            loop {
                let listener_identity = Identity::load_or_create()?;
                match sync::serve_one(&listener, &listener_identity, &mut v).await {
                    Ok(peer_id) => println!("Synced {} successfully.", peer_id.fingerprint()),
                    Err(e) => eprintln!("A peer connection failed: {e}"),
                }
            }
        })
    }
}

pub struct Join;

impl Join {
    pub fn execute(invite: String, out: PathBuf) -> std::io::Result<()> {
        let invite = InviteCode::decode(&invite).map_err(to_io_err)?;
        let addr = invite.address.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "this invite code has no address to connect to")
        })?;
        let local_identity = Identity::load_or_create()?;

        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async move {
            let mut v = sync::join(addr, &local_identity, &invite.peer_id, &out).await.map_err(to_io_err)?;
            let files = v.list_files().map_err(to_io_err)?;
            println!("Joined vault \"{}\" -- {} file(s) available:", v.summary().name, files.len());
            for f in files {
                println!("  {} ({} bytes)", f.name, f.size);
            }
            Ok(())
        })
    }
}

fn to_io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
