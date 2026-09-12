//! Revault's storage engine: the `.rvlt` binary container format, block
//! allocation, cryptography, tamper-evident hash chain, and the high-level
//! `Vault` API used by both the CLI and TUI layers.

pub mod allocator;
pub mod crypto;
pub mod error;
pub mod format;
pub mod session;
pub mod vault;

pub use error::{Result, VaultError};
pub use session::Session;
pub use vault::{FileInfo, Vault, VaultSummary};
