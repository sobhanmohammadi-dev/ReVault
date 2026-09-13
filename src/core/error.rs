use thiserror::Error;

/// Errors produced by the Revault storage engine.
///
/// Variants are intentionally coarse-grained on the *user-facing* message so
/// that we never leak sensitive material (passwords, derived keys, raw
/// plaintext) through `Display`/`Debug`. Any lower-level context that might
/// be sensitive must be stripped before it reaches one of these variants.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("the file is not a valid .rvlt container (bad magic bytes)")]
    NotARvltFile,

    #[error("unsupported .rvlt format version: {found} (supported: {min}..={max})")]
    UnsupportedVersion { found: u32, min: u32, max: u32 },

    #[error(".rvlt container is corrupted or malformed: {0}")]
    CorruptContainer(&'static str),

    #[error("checksum mismatch while reading {0}")]
    ChecksumMismatch(&'static str),

    #[error("incorrect password")]
    IncorrectPassword,

    #[error("cryptographic operation failed")]
    CryptoFailure,

    #[error("requested capacity is too small to hold vault metadata")]
    CapacityTooSmall,

    #[error("not enough free space in vault (requested {requested} bytes, available {available} bytes)")]
    InsufficientSpace { requested: u64, available: u64 },

    #[error("file table is full; vault cannot track any more files")]
    FileTableFull,

    #[error("no file named '{0}' exists in this vault")]
    FileNotFound(String),

    #[error("a file named '{0}' already exists in this vault")]
    FileAlreadyExists(String),

    #[error("integrity chain verification failed: {0}")]
    IntegrityViolation(&'static str),

    #[error("name/description/filename exceeds the maximum stored length")]
    FieldTooLong,

    #[error("vault is locked; unlock it with the correct password first")]
    VaultLocked,

    #[error("this vault was opened without admin privileges; only the vault's admin can modify it")]
    NotAuthorized,

    #[error("no matching recipient access was found for this identity")]
    AccessNotGranted,

    #[error("this identity already has access to the vault")]
    AlreadyGranted,

    #[error("recipient table is full; revoke an existing peer before granting a new one")]
    RecipientTableFull,

    #[error("remote peer reported an error: {0}")]
    Remote(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
