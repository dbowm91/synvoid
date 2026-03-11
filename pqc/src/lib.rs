//! Post-Quantum Cryptography utilities for MaluWAF
//!
//! This crate provides post-quantum cryptographic primitives, focusing on
//! ML-KEM-768/1024 (FIPS 203) for key encapsulation and ML-DSA-44 (FIPS 204) for
//! digital signatures in mesh transport communications.

pub mod kem;
pub mod keys;
pub mod test_vectors;
pub mod dsa;

pub use kem::MlKem768;
pub use kem::MlKem1024;
pub use keys::{Ciphertext, KeySizeError, PublicKey, SecretKey, SharedSecret};
pub use dsa::{MlDsa44, SigningKey, Signature, VerifyingKey, SignatureError};
