//! Wrapper sottili sulle primitive: AEAD (XChaCha20-Poly1305) e firma Ed25519.
//! Nessun algoritmo inventato: solo chiamate a librerie verificate.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

use crate::error::{AxError, Result};

/// Lunghezza del nonce di XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;
/// Overhead del tag Poly1305.
pub const TAG_LEN: usize = 16;

/// Genera `NONCE_LEN` byte casuali da un RNG di sistema.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// Cifra `plaintext` con `key` e `nonce`, legando `aad` (associated data).
/// Restituisce il ciphertext (tag incluso).
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AxError::Encrypt)
}

/// Decifra `ciphertext` (tag incluso) con `key`, `nonce` e `aad`.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AxError::Decrypt)
}

/// Firma `msg` con la chiave privata Ed25519.
pub fn sign(signing_key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    signing_key.sign(msg).to_bytes()
}

/// Verifica la firma di `msg` con la chiave pubblica.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| AxError::BadSignature)?;
    let sig = Signature::from_bytes(signature);
    vk.verify(msg, &sig).map_err(|_| AxError::BadSignature)
}
