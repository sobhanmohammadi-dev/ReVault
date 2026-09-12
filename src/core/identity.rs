//! Local participant identity for the (upcoming) network feature.
//!
//! An [`Identity`] is generated once per device and stored outside any
//! vault, at `~/.revault/identity` (or `$REVAULT_HOME/identity`) --
//! never inside a `.rvlt` file. It has two keypairs, kept deliberately
//! separate:
//!
//! * an **Ed25519 signing keypair** -- proves authorship. The vault
//!   admin's signing key is the vault's root of trust: every change a
//!   peer accepts must be signed by it.
//! * an **X25519 encryption keypair** -- used only to wrap a vault's
//!   data key for this identity (envelope encryption), so the admin can
//!   grant another identity decrypt access without ever sharing the
//!   vault password.
//!
//! A [`PeerId`] is the shareable, non-secret half of an identity (both
//! public keys) -- what you'd put in an invite string.
//!
//! NOTE: this module has not been compiled in this environment (no
//! rustc/cargo available here). The exact dalek-crate call sites --
//! `SigningKey::generate`, `StaticSecret::random_from_rng`, and the
//! `to_bytes`/`from_bytes` conversions -- are written against the
//! documented stable 2.x APIs of `ed25519-dalek` and `x25519-dalek`, but
//! should be the first thing checked against `cargo doc` output if the
//! build fails here.

use std::path::PathBuf;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core_06::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use super::error::{Result, VaultError};

pub const SIGNING_PUBLIC_LEN: usize = 32;
pub const ENCRYPTION_PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// A shareable, non-secret identifier for a participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId {
    pub signing_public: [u8; SIGNING_PUBLIC_LEN],
    pub encryption_public: [u8; ENCRYPTION_PUBLIC_LEN],
}

impl PeerId {
    /// Short, human-comparable fingerprint (first 8 bytes of
    /// SHA-256(signing_public || encryption_public), hex-encoded), so two
    /// people can read a short string aloud to confirm they have the
    /// right identity -- similar in spirit to a Signal safety number.
    pub fn fingerprint(&self) -> String {
        let hash = super::crypto::sha256_concat(&[&self.signing_public, &self.encryption_public]);
        hash[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn to_bytes(self) -> [u8; SIGNING_PUBLIC_LEN + ENCRYPTION_PUBLIC_LEN] {
        let mut out = [0u8; SIGNING_PUBLIC_LEN + ENCRYPTION_PUBLIC_LEN];
        out[..SIGNING_PUBLIC_LEN].copy_from_slice(&self.signing_public);
        out[SIGNING_PUBLIC_LEN..].copy_from_slice(&self.encryption_public);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNING_PUBLIC_LEN + ENCRYPTION_PUBLIC_LEN {
            return Err(VaultError::CorruptContainer("malformed PeerId bytes"));
        }
        let mut signing_public = [0u8; SIGNING_PUBLIC_LEN];
        let mut encryption_public = [0u8; ENCRYPTION_PUBLIC_LEN];
        signing_public.copy_from_slice(&bytes[..SIGNING_PUBLIC_LEN]);
        encryption_public.copy_from_slice(&bytes[SIGNING_PUBLIC_LEN..]);
        Ok(PeerId { signing_public, encryption_public })
    }
}

/// A local participant's full identity, including secret key material.
/// Never serialize this into a vault; it belongs only in the local
/// identity file.
pub struct Identity {
    signing: SigningKey,
    encryption: StaticSecret,
}

fn identity_file_path() -> PathBuf {
    if let Ok(p) = std::env::var("REVAULT_HOME") {
        return PathBuf::from(p).join("identity");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".revault").join("identity");
    }
    PathBuf::from(".revault").join("identity")
}

impl Identity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let encryption = StaticSecret::random_from_rng(&mut OsRng);
        Identity { signing, encryption }
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId {
            signing_public: self.signing.verifying_key().to_bytes(),
            encryption_public: *XPublicKey::from(&self.encryption).as_bytes(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    pub fn encryption_secret(&self) -> &StaticSecret {
        &self.encryption
    }

    /// Serializes both secret keys for local storage: 32-byte Ed25519
    /// seed followed by 32-byte X25519 scalar.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.encryption.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut signing_seed = [0u8; 32];
        signing_seed.copy_from_slice(&bytes[..32]);
        let mut enc_scalar = [0u8; 32];
        enc_scalar.copy_from_slice(&bytes[32..]);
        Identity {
            signing: SigningKey::from_bytes(&signing_seed),
            encryption: StaticSecret::from(enc_scalar),
        }
    }

    /// Loads the on-disk identity, generating and persisting a new one on
    /// first run. This is the normal entry point for both the admin and
    /// any peer's local identity.
    pub fn load_or_create() -> std::io::Result<Self> {
        let path = identity_file_path();
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&bytes);
                return Ok(Identity::from_bytes(&arr));
            }
        }
        let identity = Identity::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, identity.to_bytes())?;
        Ok(identity)
    }
}

/// Verifies a signature made by [`Identity::sign`] against a peer's
/// public signing key. Used to check that a chain record (or, later, a
/// handshake message) really came from the claimed identity.
pub fn verify_signature(signing_public: &[u8; SIGNING_PUBLIC_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(signing_public).map_err(|_| VaultError::CryptoFailure)?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| VaultError::IntegrityViolation("signature does not match the claimed identity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_usable_keys() {
        let identity = Identity::generate();
        let peer_id = identity.peer_id();
        let msg = b"hello, peer";
        let sig = identity.sign(msg);
        assert!(verify_signature(&peer_id.signing_public, msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let identity = Identity::generate();
        let peer_id = identity.peer_id();
        let sig = identity.sign(b"original message");
        assert!(verify_signature(&peer_id.signing_public, b"different message", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig = a.sign(b"hello");
        assert!(verify_signature(&b.peer_id().signing_public, b"hello", &sig).is_err());
    }

    #[test]
    fn identity_bytes_roundtrip_preserves_peer_id() {
        let identity = Identity::generate();
        let peer_id_before = identity.peer_id();
        let bytes = identity.to_bytes();
        let restored = Identity::from_bytes(&bytes);
        assert_eq!(restored.peer_id(), peer_id_before);
    }

    #[test]
    fn peer_id_bytes_roundtrip() {
        let identity = Identity::generate();
        let peer_id = identity.peer_id();
        let bytes = peer_id.to_bytes();
        let restored = PeerId::from_bytes(&bytes).unwrap();
        assert_eq!(restored, peer_id);
    }

    #[test]
    fn fingerprint_is_stable_and_differs_between_identities() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(a.peer_id().fingerprint(), a.peer_id().fingerprint());
        assert_ne!(a.peer_id().fingerprint(), b.peer_id().fingerprint());
    }

    #[test]
    fn load_or_create_persists_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("REVAULT_HOME", dir.path());
        }
        let first = Identity::load_or_create().unwrap().peer_id();
        let second = Identity::load_or_create().unwrap().peer_id();
        assert_eq!(first, second, "second load should reuse the persisted identity");
        unsafe {
            std::env::remove_var("REVAULT_HOME");
        }
    }
}
