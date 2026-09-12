//! Hybrid Ed25519 + ML-DSA-44 signature support for mesh messages.
//!
//! Phase 27: the canonical `HybridSignature` envelope value type now lives in
//! `synvoid-mesh-protocol` (low-capability wire vocabulary). This module
//! re-exports that canonical type for compatibility and keeps the
//! mesh-side runtime helpers (signing traits + `synvoid-integrity` bridges)
//! that require the `pqc` runtime and must NOT move downward.

pub use synvoid_integrity::signing::{
    sign_ed25519, sign_ml_dsa, verify_ed25519, verify_ed25519_raw, verify_ml_dsa,
};

// Canonical envelope owned by the protocol crate (value semantics only).
pub use synvoid_mesh_protocol::{
    HybridSignature, HybridSignatureError, ED25519_SIGNATURE_SIZE, ML_DSA_SIGNATURE_SIZE,
};

pub trait HybridSigner: Send + Sync {
    fn sign_hybrid(&self, content: &[u8]) -> HybridSignature;
    fn verify_hybrid(&self, content: &[u8], signature: &HybridSignature) -> bool;
    fn has_ml_dsa(&self) -> bool;
    fn public_key(&self) -> &str;
}

pub trait MlDsaSigner: Send + Sync {
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

pub trait MlDsaVerifier: Send + Sync {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signature_serialization() {
        let sig = HybridSignature::new(
            vec![0u8; ED25519_SIGNATURE_SIZE],
            vec![1u8; ML_DSA_SIGNATURE_SIZE],
            "test_ed_key".to_string(),
            Some("test_ml_key".to_string()),
        );

        let bytes = sig.to_bytes();
        let recovered = HybridSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.ed25519_signature, recovered.ed25519_signature);
        assert_eq!(sig.ml_dsa_signature, recovered.ml_dsa_signature);
        assert_eq!(sig.ed25519_public_key, recovered.ed25519_public_key);
        assert_eq!(sig.ml_dsa_public_key, recovered.ml_dsa_public_key);
    }

    #[test]
    fn test_hybrid_signature_ed25519_only() {
        let sig = HybridSignature::ed25519_only(
            vec![0u8; ED25519_SIGNATURE_SIZE],
            "test_key".to_string(),
        );

        assert!(!sig.has_ml_dsa());
        assert!(sig.ml_dsa_signature.is_empty());
    }

    #[test]
    fn test_serialized_size() {
        let sig = HybridSignature::new(
            vec![0u8; ED25519_SIGNATURE_SIZE],
            vec![1u8; ML_DSA_SIGNATURE_SIZE],
            "test_ed".to_string(),
            Some("test_ml".to_string()),
        );

        let expected = 4 + ED25519_SIGNATURE_SIZE + 4 + ML_DSA_SIGNATURE_SIZE + 4 + 7 + 4 + 7;
        assert_eq!(sig.serialized_size(), expected);
    }
}
