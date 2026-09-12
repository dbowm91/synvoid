//! Typed keystore errors (Phase 30 Part B).
//!
//! All failures are typed; HSM-required paths fail closed and never fall
//! back silently to software keys.

use thiserror::Error;

/// Typed outcome for every keystore operation.
#[derive(Debug, Clone, Error)]
pub enum KeystoreError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("unsupported algorithm for signing: {0}")]
    UnsupportedAlgorithm(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("HSM required but unavailable: {0}")]
    HsmRequired(String),
    #[error("HSM error: {0}")]
    Hsm(String),
    #[error("key management error: {0}")]
    Management(String),
    #[error("RNG failure: {0}")]
    Entropy(String),
}
