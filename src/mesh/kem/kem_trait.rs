//! KEM (Key Encapsulation Mechanism) abstraction
//!
//! Provides a generic trait for implementing different KEM algorithms
//! (e.g., ML-KEM-768, X25519) with a unified interface.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KemError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
    #[error("Invalid ciphertext size: expected {expected}, got {actual}")]
    InvalidCiphertextSize { expected: usize, actual: usize },
}

pub trait KemSession: Send + Sync + Clone + 'static {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey: AsRef<[u8]> + Clone;
    type SharedSecret: AsRef<[u8]> + Clone;

    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), KemError>;

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Self::SharedSecret), KemError>;

    fn decapsulate(ct: &[u8], sk: &Self::SecretKey) -> Result<Self::SharedSecret, KemError>;

    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const CIPHERTEXT_SIZE: usize;
    const SHARED_SECRET_SIZE: usize;
}
