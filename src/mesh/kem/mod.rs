//! KEM (Key Encapsulation Mechanism) module
//!
//! Provides abstractions for post-quantum key encapsulation with support
//! for different algorithms (ML-KEM-768, etc.).

pub mod kem_trait;
pub mod ml_kem;

pub use kem_trait::{KemError, KemSession};
pub use ml_kem::{MlKem768, MlKem768PublicKey, MlKem768SecretKey, MlKem768SharedSecret};
