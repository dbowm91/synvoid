//! Synchronous deterministic Ed25519 value semantics.
//!
//! `ProtocolSigner` is the low-level counterpart to `synvoid-mesh`'s
//! `MeshMessageSigner` runtime service. It owns key material and performs
//! synchronous Ed25519 sign/verify with no `CryptoVerificationPool`, no ML-DSA
//! runtime, no config access, and no async offload.
//!
//! Hybrid/ML-DSA verification stays in `synvoid-mesh` (`verify_hybrid*`,
//! `CryptoVerificationPool`). This crate exposes `verify_hybrid_envelope_shape`
//! only as a structural check (parsable envelope), never as trust.

use base64::Engine;
use ed25519_dalek::{Signer, Verifier};

use crate::hybrid::HybridSignature;

/// Typed signer errors (wire-contract move preserves `MeshMessageSigner`
/// semantics for the Ed25519-only path).
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },
    #[error("Message is not signable")]
    NotSignable,
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
}

/// Ed25519-only signer value. Synchronous and deterministic.
#[derive(Clone)]
pub struct ProtocolSigner {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key_bytes: Vec<u8>,
}

impl ProtocolSigner {
    pub fn new(secret_key: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_bytes: verifying_key.as_bytes().to_vec(),
        }
    }

    pub fn from_secret(secret_key: ed25519_dalek::SecretKey) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_bytes: verifying_key.as_bytes().to_vec(),
        }
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::fill(&mut key);
        key
    }

    pub fn sign(&self, content: &[u8]) -> Vec<u8> {
        self.signing_key.sign(content).to_bytes().to_vec()
    }

    /// Verify raw Ed25519 `signature` over `content` with raw 32-byte `public_key`.
    /// Returns false (fail-closed) on any length/key parse failure.
    pub fn verify(&self, content: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        verify_ed25519(content, signature, public_key)
    }

    /// Verify either a hybrid envelope or a raw Ed25519 signature.
    ///
    /// For hybrid envelopes this checks the **Ed25519 half only**; ML-DSA trust
    /// must be established by `synvoid-mesh` verification. This mirrors the
    /// `MeshMessageSigner::verify_auto` dispatch shape without claiming PQ trust.
    pub fn verify_auto(&self, content: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() > 64 {
            if let Ok(hybrid) = HybridSignature::from_bytes(signature) {
                return verify_hybrid_ed25519_half(content, &hybrid);
            }
        }
        self.verify(content, signature, public_key)
    }

    pub fn get_public_key(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.verifying_key_bytes)
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key_bytes.clone()
    }
}

/// Free-function Ed25519 verification (fail-closed, constant-shape).
pub fn verify_ed25519(content: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != 64 || public_key.len() != 32 {
        return false;
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature);
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(public_key);
    match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
        Ok(pk) => pk
            .verify(content, &ed25519_dalek::Signature::from_bytes(&sig_array))
            .is_ok(),
        Err(_) => false,
    }
}

/// Verify the Ed25519 half of a hybrid envelope. Returns false when the
/// embedded public key is not valid base64 or verification fails. ML-DSA half
/// is intentionally NOT trusted here.
pub fn verify_hybrid_ed25519_half(content: &[u8], hybrid: &HybridSignature) -> bool {
    let pk_bytes =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&hybrid.ed25519_public_key) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
    verify_ed25519(content, &hybrid.ed25519_signature, &pk_bytes)
}
