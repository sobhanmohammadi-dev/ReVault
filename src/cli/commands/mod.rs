pub mod network;
pub mod start;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Launch the interactive TUI.
    Start,

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
