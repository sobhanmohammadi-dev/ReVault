//! Cryptographic primitives used by the .rvlt format.
//!
//! * Key derivation: Argon2id (via the `argon2` crate) turns the user's
//!   password + a random per-vault salt into a 256-bit master key.
//! * Confidentiality: AES-256-GCM (via `aes-gcm`) is used as an AEAD cipher
//!   for both the password verifier blob and every data block.
//! * Integrity: SHA-256 (via `sha2`) is used for the tamper-evident hash
//!   chain and for plaintext file hashes.
//!
//! No custom cryptography is implemented here; this module only wires
//! together well-maintained crates and is careful about key/plaintext
//! lifetime and never appearing in `Debug`/logs.
//!
//! `Key::from_slice`/`Nonce::from_slice` are deprecated in favor of
//! `TryFrom` as of a recent `aes-gcm` point release; both still work
//! and this is a cosmetic warning, not a soundness issue, so it's
//! silenced here rather than churning every call site.
#![allow(deprecated)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use rand_core_06::OsRng as OsRng06;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use super::error::{Result, VaultError};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Argon2id parameters stored in the header so a vault created with one set
/// of tuning parameters can still be opened later even if defaults change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // ~19 MiB, 2 passes, single lane: a reasonable interactive default
        // per the Argon2 RFC 9106 recommendations for password hashing.
        Self {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// The derived master key. Zeroized on drop so it does not linger in memory
/// longer than necessary.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; KEY_LEN]);

impl MasterKey {
    pub fn derive(password: &[u8], salt: &[u8; SALT_LEN], params: Argon2Params) -> Result<Self> {
        let argon2_params = Params::new(
            params.m_cost_kib,
            params.t_cost,
            params.p_cost,
            Some(KEY_LEN),
        )
        .map_err(|_| VaultError::CryptoFailure)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(password, salt, &mut out)
            .map_err(|_| VaultError::CryptoFailure)?;
        Ok(MasterKey(out))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
    }

    /// Encrypt `plaintext` with a random 12-byte nonce. Returns
    /// `nonce || ciphertext_with_tag`.
    pub fn encrypt_random_nonce(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultError::CryptoFailure)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_random_nonce(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(VaultError::CorruptContainer("ciphertext blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultError::IncorrectPassword)
    }

    /// Encrypt one on-disk block. The nonce is *derived deterministically*
    /// from `(file_id, block_index)`, which is safe because that pair is
    /// unique for the lifetime of the key: every file gets a fresh UUIDv7
    /// on creation, so the same (file_id, block_index) pair is never
    /// encrypted twice under the same master key.
    pub fn encrypt_block(&self, file_id: u128, block_index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::block_nonce(file_id, block_index);
        self.cipher()
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| VaultError::CryptoFailure)
    }

    pub fn decrypt_block(
        &self,
        file_id: u128,
        block_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = Self::block_nonce(file_id, block_index);
        self.cipher()
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| VaultError::CorruptContainer("block failed authentication (tampered or wrong key)"))
    }

    fn block_nonce(file_id: u128, block_index: u64) -> [u8; NONCE_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(b"revault-block-nonce-v1");
        hasher.update(file_id.to_le_bytes());
        hasher.update(block_index.to_le_bytes());
        let digest = hasher.finalize();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&digest[..NONCE_LEN]);
        nonce
    }
}

impl MasterKey {
    /// Wraps an already-derived 32-byte key (used for the vault's actual
    /// content key -- the DEK -- as opposed to a password-derived KEK).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        MasterKey(bytes)
    }

    /// Exposes the raw key bytes. Used only to wrap the DEK for a newly
    /// granted recipient (see [`wrap_dek_for_recipient`]) -- never logged,
    /// never written to disk in the clear.
    pub fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub const WRAPPED_DEK_LEN: usize = 32 /* ephemeral X25519 pubkey */ + NONCE_LEN + KEY_LEN + TAG_LEN;

/// Derives a symmetric wrapping key from an X25519 shared secret.
///
/// This is a single-step SHA-256-based KDF, not a formal HKDF. That's an
/// intentional, documented simplification for the "small trusted set of
/// devices" threat model this targets, to avoid pulling in another crate
/// whose exact API we can't verify without a compiler in this
/// environment. Swap in a proper HKDF (e.g. the `hkdf` crate) before
/// this is ever exposed to a broader / adversarial network.
fn derive_wrap_key(shared_secret: &[u8]) -> [u8; KEY_LEN] {
    sha256_concat(&[shared_secret, b"revault-dek-wrap-v1"])
}

/// Wraps a vault's DEK for a specific recipient's X25519 public key, so
/// only that recipient's matching private key can recover it. Uses a
/// fresh ephemeral keypair per call (the ephemeral public key travels
/// alongside the ciphertext so the recipient can redo the same
/// Diffie-Hellman on their side) -- a minimal ECIES-style construction
/// built from well-maintained primitives (X25519 + AES-256-GCM), not a
/// custom cryptographic algorithm.
pub fn wrap_dek_for_recipient(recipient_encryption_pub: &[u8; 32], dek: &[u8; KEY_LEN]) -> Result<[u8; WRAPPED_DEK_LEN]> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng06);
    let ephemeral_public = XPublicKey::from(&ephemeral_secret);
    let recipient_public = XPublicKey::from(*recipient_encryption_pub);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    let wrap_key = derive_wrap_key(shared.as_bytes());

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), dek.as_slice())
        .map_err(|_| VaultError::CryptoFailure)?;

    let mut out = [0u8; WRAPPED_DEK_LEN];
    out[..32].copy_from_slice(ephemeral_public.as_bytes());
    out[32..32 + NONCE_LEN].copy_from_slice(&nonce_bytes);
    out[32 + NONCE_LEN..].copy_from_slice(&ciphertext);
    Ok(out)
}

/// The recipient-side counterpart of [`wrap_dek_for_recipient`].
pub fn unwrap_dek_for_recipient(recipient_secret: &StaticSecret, wrapped: &[u8; WRAPPED_DEK_LEN]) -> Result<[u8; KEY_LEN]> {
    let mut ephemeral_pub_bytes = [0u8; 32];
    ephemeral_pub_bytes.copy_from_slice(&wrapped[..32]);
    let ephemeral_public = XPublicKey::from(ephemeral_pub_bytes);

    let nonce_bytes = &wrapped[32..32 + NONCE_LEN];
    let ciphertext = &wrapped[32 + NONCE_LEN..];

    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    let wrap_key = derive_wrap_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| VaultError::AccessNotGranted)?;
    if plaintext.len() != KEY_LEN {
        return Err(VaultError::CorruptContainer("unwrapped DEK has the wrong length"));
    }
    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// A secret byte buffer (e.g. a password copy) that zeroizes on drop.
#[derive(ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);

impl From<&str> for SecretBytes {
    fn from(s: &str) -> Self {
        SecretBytes(s.as_bytes().to_vec())
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> Argon2Params {
        // Tiny params purely so unit tests don't take forever; production
        // code paths use Argon2Params::default().
        Argon2Params {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn derive_is_deterministic_for_same_salt() {
        let salt = [7u8; SALT_LEN];
        let k1 = MasterKey::derive(b"hunter2", &salt, fast_params()).unwrap();
        let k2 = MasterKey::derive(b"hunter2", &salt, fast_params()).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn derive_differs_for_different_passwords() {
        let salt = [7u8; SALT_LEN];
        let k1 = MasterKey::derive(b"hunter2", &salt, fast_params()).unwrap();
        let k2 = MasterKey::derive(b"hunter3", &salt, fast_params()).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn random_nonce_roundtrip() {
        let key = MasterKey::derive(b"pw", &[1u8; SALT_LEN], fast_params()).unwrap();
        let blob = key.encrypt_random_nonce(b"hello world", b"aad").unwrap();
        let out = key.decrypt_random_nonce(&blob, b"aad").unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn random_nonce_rejects_tampering() {
        let key = MasterKey::derive(b"pw", &[1u8; SALT_LEN], fast_params()).unwrap();
        let mut blob = key.encrypt_random_nonce(b"hello world", b"aad").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(key.decrypt_random_nonce(&blob, b"aad").is_err());
    }

    #[test]
    fn wrong_password_fails_verifier() {
        let salt = random_salt();
        let key_a = MasterKey::derive(b"correct-password", &salt, fast_params()).unwrap();
        let blob = key_a.encrypt_random_nonce(b"verifier", b"revault-verifier").unwrap();

        let key_b = MasterKey::derive(b"wrong-password", &salt, fast_params()).unwrap();
        assert!(key_b.decrypt_random_nonce(&blob, b"revault-verifier").is_err());
    }

    #[test]
    fn block_roundtrip_and_distinct_nonces() {
        let key = MasterKey::derive(b"pw", &[2u8; SALT_LEN], fast_params()).unwrap();
        let ct1 = key.encrypt_block(42, 0, b"block zero contents").unwrap();
        let ct2 = key.encrypt_block(42, 1, b"block one contents!").unwrap();
        assert_ne!(ct1, ct2);

        let pt1 = key.decrypt_block(42, 0, &ct1).unwrap();
        assert_eq!(pt1, b"block zero contents");

        // Ciphertext for block 0 must not decrypt as block 1 (nonce mismatch
        // -> AEAD auth failure).
        assert!(key.decrypt_block(42, 1, &ct1).is_err());
    }

    #[test]
    fn block_ciphertext_authenticates_against_tampering() {
        let key = MasterKey::derive(b"pw", &[3u8; SALT_LEN], fast_params()).unwrap();
        let mut ct = key.encrypt_block(1, 0, b"secret payload bytes").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(key.decrypt_block(1, 0, &ct).is_err());
    }

    #[test]
    fn wrap_and_unwrap_dek_roundtrip() {
        let recipient_secret = StaticSecret::random_from_rng(&mut OsRng06);
        let recipient_public = *XPublicKey::from(&recipient_secret).as_bytes();
        let dek = [42u8; KEY_LEN];

        let wrapped = wrap_dek_for_recipient(&recipient_public, &dek).unwrap();
        let unwrapped = unwrap_dek_for_recipient(&recipient_secret, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn unwrap_fails_for_wrong_recipient() {
        let real_recipient = StaticSecret::random_from_rng(&mut OsRng06);
        let real_public = *XPublicKey::from(&real_recipient).as_bytes();
        let dek = [7u8; KEY_LEN];
        let wrapped = wrap_dek_for_recipient(&real_public, &dek).unwrap();

        let attacker_secret = StaticSecret::random_from_rng(&mut OsRng06);
        assert!(unwrap_dek_for_recipient(&attacker_secret, &wrapped).is_err());
    }

    #[test]
    fn wrap_produces_different_ciphertext_each_time() {
        let recipient_secret = StaticSecret::random_from_rng(&mut OsRng06);
        let recipient_public = *XPublicKey::from(&recipient_secret).as_bytes();
        let dek = [9u8; KEY_LEN];
        let a = wrap_dek_for_recipient(&recipient_public, &dek).unwrap();
        let b = wrap_dek_for_recipient(&recipient_public, &dek).unwrap();
        assert_ne!(a, b, "fresh ephemeral key + nonce should differ each call");
    }

    #[test]
    fn block_encryption_handles_empty_plaintext() {
        // Empty files exist (0 bytes of content); block encryption must
        // not choke on a zero-length payload.
        let key = MasterKey::derive(b"pw", &[5u8; SALT_LEN], fast_params()).unwrap();
        let ct = key.encrypt_block(1, 0, b"").unwrap();
        let pt = key.decrypt_block(1, 0, &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn different_block_indices_are_not_interchangeable_ciphertext() {
        let key = MasterKey::derive(b"pw", &[6u8; SALT_LEN], fast_params()).unwrap();
        let ct_a = key.encrypt_block(1, 5, b"same file, block five").unwrap();
        let ct_b = key.encrypt_block(1, 6, b"same file, block five").unwrap();
        assert_ne!(ct_a, ct_b, "same file + same plaintext but different block index must differ");
    }
}
