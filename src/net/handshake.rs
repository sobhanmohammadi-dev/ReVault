//! A minimal authenticated key exchange plus encrypted framing, built
//! from the same vetted primitives as the rest of Revault (X25519 +
//! Ed25519 + AES-256-GCM) rather than a full protocol-framework
//! implementation.
//!
//! **Important caveat**, stated plainly: this is a small, from-scratch
//! construction, not a formally analyzed protocol like Noise or TLS. It
//! is judged adequate for the threat model this targets -- a small
//! trusted set of devices, where the peer's `PeerId` is exchanged out of
//! band via an invite code before ever connecting. MITM resistance comes
//! from the caller checking the responder's `PeerId` against the one
//! from that invite (see `initiator` below), not from anything the
//! handshake protocol itself proves about network routing. Before this
//! is ever exposed to a broader/adversarial network, replace it with a
//! real Noise handshake (e.g. via the `snow` crate).
//!
//! NOTE: like the rest of the network layer, this has not been compiled
//! in this environment -- see the crate-level caveats in
//! `docs/ARCHITECTURE_NETWORK.md`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand_core_06::OsRng as OsRng06;
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

use crate::core::error::{Result, VaultError};
use crate::core::identity::{self, Identity, PeerId};

use super::protocol::{read_frame, write_frame};

const HELLO_LEN: usize = 64 + 32 + 64; // PeerId bytes + ephemeral pubkey + Ed25519 signature

struct Hello {
    peer_id: PeerId,
    ephemeral_pub: [u8; 32],
    signature: [u8; 64],
}

impl Hello {
    fn build(local_identity: &Identity, ephemeral_pub: [u8; 32]) -> Self {
        let signature = local_identity.sign(&ephemeral_pub);
        Hello { peer_id: local_identity.peer_id(), ephemeral_pub, signature }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HELLO_LEN);
        buf.extend_from_slice(&self.peer_id.to_bytes());
        buf.extend_from_slice(&self.ephemeral_pub);
        buf.extend_from_slice(&self.signature);
        buf
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() != HELLO_LEN {
            return Err(VaultError::CorruptContainer("malformed handshake hello"));
        }
        let peer_id = PeerId::from_bytes(&buf[0..64])?;
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&buf[64..96]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[96..160]);
        Ok(Hello { peer_id, ephemeral_pub, signature })
    }

    /// Proves the sender holds the private signing key for the claimed
    /// `peer_id` -- NOT that they are the specific peer the caller
    /// intended to reach (see module docs).
    fn verify(&self) -> Result<()> {
        identity::verify_signature(&self.peer_id.signing_public, &self.ephemeral_pub, &self.signature)
    }
}

/// An authenticated, encrypted duplex channel to a peer, layered over
/// any async byte stream (in practice, a `TcpStream`).
pub struct SecureChannel<S> {
    stream: S,
    key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
    /// 0 or 1. The two ends of a connection always end up with opposite
    /// parities, which guarantees their nonce spaces (built from
    /// `counter * 2 + parity`) never collide even though both directions
    /// share the same derived key.
    send_parity: u8,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureChannel<S> {
    /// Runs the handshake as the connection *initiator* (the side that
    /// dialed out). `expected_peer` should come from an out-of-band
    /// invite code -- this check is what actually prevents talking to an
    /// impostor, not the handshake alone.
    pub async fn initiator(mut stream: S, my_identity: &Identity, expected_peer: &PeerId) -> Result<(Self, PeerId)> {
        let my_ephemeral = EphemeralSecret::random_from_rng(&mut OsRng06);
        let my_ephemeral_pub = *XPublicKey::from(&my_ephemeral).as_bytes();
        let hello = Hello::build(my_identity, my_ephemeral_pub);
        write_frame(&mut stream, &hello.encode()).await.map_err(VaultError::Io)?;

        let their_bytes = read_frame(&mut stream).await.map_err(VaultError::Io)?;
        let their_hello = Hello::decode(&their_bytes)?;
        their_hello.verify()?;
        if &their_hello.peer_id != expected_peer {
            return Err(VaultError::AccessNotGranted);
        }

        let their_pub = XPublicKey::from(their_hello.ephemeral_pub);
        let shared = my_ephemeral.diffie_hellman(&their_pub);
        let key = derive_session_key(shared.as_bytes());

        let peer_id = their_hello.peer_id;
        Ok((SecureChannel { stream, key, send_counter: 0, recv_counter: 0, send_parity: 0 }, peer_id))
    }

    /// Runs the handshake as the connection *responder* (the side that
    /// accepted an incoming connection). Returns the caller's `PeerId` so
    /// the application layer can decide whether that identity is
    /// actually granted access to whatever they're asking for -- the
    /// handshake itself authenticates identity, not authorization.
    pub async fn responder(mut stream: S, my_identity: &Identity) -> Result<(Self, PeerId)> {
        let their_bytes = read_frame(&mut stream).await.map_err(VaultError::Io)?;
        let their_hello = Hello::decode(&their_bytes)?;
        their_hello.verify()?;

        let my_ephemeral = EphemeralSecret::random_from_rng(&mut OsRng06);
        let my_ephemeral_pub = *XPublicKey::from(&my_ephemeral).as_bytes();
        let hello = Hello::build(my_identity, my_ephemeral_pub);
        write_frame(&mut stream, &hello.encode()).await.map_err(VaultError::Io)?;

        let their_pub = XPublicKey::from(their_hello.ephemeral_pub);
        let shared = my_ephemeral.diffie_hellman(&their_pub);
        let key = derive_session_key(shared.as_bytes());

        let peer_id = their_hello.peer_id;
        Ok((SecureChannel { stream, key, send_counter: 0, recv_counter: 0, send_parity: 1 }, peer_id))
    }

    fn send_nonce(&mut self) -> [u8; 12] {
        let n = self.send_counter * 2 + self.send_parity as u64;
        self.send_counter += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    fn recv_nonce(&mut self) -> [u8; 12] {
        let recv_parity = 1 - self.send_parity;
        let n = self.recv_counter * 2 + recv_parity as u64;
        self.recv_counter += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let nonce = self.send_nonce();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| VaultError::CryptoFailure)?;
        write_frame(&mut self.stream, &ciphertext).await.map_err(VaultError::Io)
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let ciphertext = read_frame(&mut self.stream).await.map_err(VaultError::Io)?;
        let nonce = self.recv_nonce();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
            .map_err(|_| VaultError::CryptoFailure)
    }
}

fn derive_session_key(shared_secret: &[u8]) -> [u8; 32] {
    // Same documented simplification as the DEK-wrapping KDF in
    // core::crypto: single-step SHA-256, not a formal HKDF.
    crate::core::crypto::sha256_concat(&[shared_secret, b"revault-session-v1"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn handshake_and_encrypted_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_identity = Identity::generate();
        let client_identity = Identity::generate();
        let client_expected_server = server_identity.peer_id();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut channel, client_peer_id) = SecureChannel::responder(stream, &server_identity).await.unwrap();
            let msg = channel.recv().await.unwrap();
            assert_eq!(msg, b"hello from client");
            channel.send(b"hello from server").await.unwrap();
            client_peer_id
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut client_channel, server_peer_id) =
            SecureChannel::initiator(stream, &client_identity, &client_expected_server).await.unwrap();
        client_channel.send(b"hello from client").await.unwrap();
        let reply = client_channel.recv().await.unwrap();
        assert_eq!(reply, b"hello from server");

        let observed_client_peer_id = server_task.await.unwrap();
        assert_eq!(observed_client_peer_id, client_identity.peer_id());
        assert_eq!(server_peer_id, client_expected_server);
    }

    #[tokio::test]
    async fn initiator_rejects_unexpected_peer_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_identity = Identity::generate();
        let wrong_expected_peer = Identity::generate().peer_id(); // not the server's real identity

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // The responder side will succeed at its half; the initiator
            // is the one that should catch the mismatch.
            let _ = SecureChannel::responder(stream, &server_identity).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let client_identity = Identity::generate();
        let result = SecureChannel::initiator(stream, &client_identity, &wrong_expected_peer).await;
        assert!(matches!(result, Err(VaultError::AccessNotGranted)));

        let _ = server_task.await;
    }
}
