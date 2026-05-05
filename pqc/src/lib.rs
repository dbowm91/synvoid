//! Post-Quantum Cryptography utilities for SynVoid
//!
//! This crate provides post-quantum cryptographic primitives, focusing on
//! ML-KEM-768/1024 (FIPS 203) for key encapsulation and ML-DSA-44 (FIPS 204) for
//! digital signatures in mesh transport communications.

pub mod dsa;
pub mod kem;
pub mod keys;
pub mod test_vectors;

pub use dsa::{MlDsa44, Signature, SignatureError, SigningKey, VerifyingKey};
pub use kem::MlKem1024;
pub use kem::MlKem768;
pub use keys::{Ciphertext, KeySizeError, PublicKey, SecretKey, SharedSecret};
