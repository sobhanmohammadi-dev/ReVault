pub mod network;
pub mod start;
pub mod vault;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Launch the interactive TUI.
    Start,

    // ---- Vault management (mirrors the Vaults tab) ----
    /// Create a new vault.
    Create {
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        /// e.g. "10 GB", "500 MB", "1 TB", or a bare byte count.
        #[arg(long)]
        capacity: String,
        #[arg(long)]
        password: String,
    },

    /// List the files stored in a vault.
    List {
        vault: PathBuf,
        #[arg(long)]
        password: String,
    },

    /// Verify a vault's integrity: hash-chain linkage, every record's
    /// admin signature, and every stored file's content hash.
    Verify {
        vault: PathBuf,
        #[arg(long)]
        password: String,
    },

    /// Add a file to a vault.
    Add {
        vault: PathBuf,
        #[arg(long)]
        password: String,
        /// Path to the file on disk to import.
        source: PathBuf,
        /// Name to store it under inside the vault.
        name: String,
    },

    /// Replace a stored file's contents.
    Update {
        vault: PathBuf,
        #[arg(long)]
        password: String,
        /// Path to the file on disk with the new contents.
        source: PathBuf,
        /// Name of the existing file inside the vault to replace.
        name: String,
    },

    /// Delete a file from a vault.
    Delete {
        vault: PathBuf,
        #[arg(long)]
        password: String,
        name: String,
    },

    // ---- Network (mirrors the Network tab) ----
    /// Print this device's shareable identity/invite code.
    Whoami {
        /// Include this address in the invite so a peer can dial it
        /// directly (use the same address you pass to `serve`).
        #[arg(long)]
        listen: Option<SocketAddr>,
    },

    /// Grant a peer identity decrypt access to a vault.
    Grant {
        vault: PathBuf,
        #[arg(long)]
        password: String,
        /// The invite code the peer shared with you (from `whoami`).
        #[arg(long)]
        peer: String,
    },

    /// Revoke a peer's access. Rotates the vault's encryption key and
    /// re-encrypts its contents, so the peer's existing local copy
    /// becomes unreadable too, not just cut off from future syncs.
    Revoke {
        vault: PathBuf,
        #[arg(long)]
        password: String,
        /// The invite code of the peer to revoke.
        #[arg(long)]
        peer: String,
    },

    /// Serve a vault to granted peers over the network.
    Serve {
        vault: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        listen: SocketAddr,
    },

    /// Join a vault as a granted peer, given an invite code that
    /// includes the admin's address (from `serve`/`whoami --listen`).
    Join {
        invite: String,
        /// Where to write the local replica.
        out: PathBuf,
    },
}

/// Shared by every CLI command that surfaces a `core::VaultError` (or
/// any other displayable error) as a plain `std::io::Error`, so `main`
/// can propagate everything uniformly with `?`.
pub(crate) fn to_io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
