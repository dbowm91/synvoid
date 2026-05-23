//! ML-DSA wrapper for mesh message signing.
//!
//! This module provides a simplified interface for ML-DSA-44 signing
//! that integrates with the pqc crate used elsewhere in the codebase.

use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, Verifier};
use pqc::{MlDsa44, Signature, SigningKey, VerifyingKey};

use crate::mesh::config::GlobalNodeConfig;

pub type MlDsaSigningKeyType = SigningKey;
pub type MlDsaVerifyingKeyType = VerifyingKey;

#[derive(Clone, Default)]
pub struct MeshMlDsaSigner {
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
}

impl MeshMlDsaSigner {
    pub fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        }
    }

    pub fn from_config(config: &GlobalNodeConfig) -> Result<Self, String> {
        let signing_key = if let Some(ref sk_b64) = config.ml_dsa_private_key_base64 {
            Some(SigningKey::from_base64(sk_b64).map_err(|e| e.to_string())?)
        } else {
            None
        };

        let verifying_key = if let Some(ref vk_b64) = config.ml_dsa_public_key_base64 {
            Some(VerifyingKey::from_base64(vk_b64).map_err(|e| e.to_string())?)
        } else {
            signing_key.as_ref().map(|sk| sk.verifying_key())
        };

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn generate() -> Self {
        let (verifying_key, signing_key) =
            MlDsa44::generate_keypair().expect("ML-DSA key generation failed");
        Self {
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let key = self.signing_key.as_ref()?;
        let sig = MlDsa44::sign(key, message).ok()?;
        Some(sig.as_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let key = match &self.verifying_key {
            Some(k) => k,
            None => return false,
        };

        let sig = match Signature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        MlDsa44::verify(key, message, &sig).is_ok()
    }

    pub fn has_signing_key(&self) -> bool {
        self.signing_key.is_some()
    }

    pub fn has_verifying_key(&self) -> bool {
        self.verifying_key.is_some()
    }

    pub fn verifying_key_base64(&self) -> Option<String> {
        self.verifying_key.as_ref().map(|k| k.to_base64())
    }

    pub fn signing_key_base64(&self) -> Option<String> {
        self.signing_key.as_ref().map(|k| k.to_base64())
    }
}

pub struct MeshMlDsaVerifier {
    verifying_key: VerifyingKey,
}

impl MeshMlDsaVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    pub fn from_base64(b64: &str) -> Result<Self, String> {
        let verifying_key = VerifyingKey::from_base64(b64).map_err(|e| e.to_string())?;
        Ok(Self::new(verifying_key))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig = match Signature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        MlDsa44::verify(&self.verifying_key, message, &sig).is_ok()
    }
}

#[derive(Clone)]
pub struct MeshHybridSigner {
    ed25519_signing_key: ed25519_dalek::SigningKey,
    ed25519_verifying_key_bytes: Vec<u8>,
    ml_dsa_signer: Option<Arc<MeshMlDsaSigner>>,
}

impl MeshHybridSigner {
    pub fn new(
        ed25519_signing_key: ed25519_dalek::SigningKey,
        ed25519_verifying_key_bytes: Vec<u8>,
        ml_dsa_signer: Option<Arc<MeshMlDsaSigner>>,
    ) -> Self {
        Self {
            ed25519_signing_key,
            ed25519_verifying_key_bytes,
            ml_dsa_signer,
        }
    }

    pub fn sign(&self, content: &[u8]) -> Vec<u8> {
        let ed25519_sig = self.ed25519_signing_key.sign(content);
        ed25519_sig.to_bytes().to_vec()
    }

    pub fn sign_with_ml_dsa(
        &self,
        content: &[u8],
    ) -> crate::mesh::hybrid_signature::HybridSignature {
        use crate::mesh::hybrid_signature::HybridSignature;

        let ed25519_sig = self.sign(content);
        let ml_dsa_sig = self
            .ml_dsa_signer
            .as_ref()
            .and_then(|s| s.sign(content))
            .unwrap_or_default();

        let ed_pk_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&self.ed25519_verifying_key_bytes);

        let ml_pk_base64 = self
            .ml_dsa_signer
            .as_ref()
            .and_then(|s| s.verifying_key_base64());

        HybridSignature::new(ed25519_sig, ml_dsa_sig, ed_pk_base64, ml_pk_base64)
    }

    pub fn verify_ed25519(&self, content: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 || self.ed25519_verifying_key_bytes.len() != 32 {
            return false;
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature);

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&self.ed25519_verifying_key_bytes);

        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
            Ok(pk) => pk
                .verify(content, &ed25519_dalek::Signature::from_bytes(&sig_array))
                .is_ok(),
            Err(_) => false,
        }
    }

    pub fn verify_hybrid(
        &self,
        content: &[u8],
        signature: &crate::mesh::hybrid_signature::HybridSignature,
    ) -> bool {
        // Verify Ed25519 first
        let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&signature.ed25519_public_key)
        {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        if !self.verify_ed25519_explicit(content, &signature.ed25519_signature, &pk_bytes) {
            return false;
        }

        if signature.has_ml_dsa() {
            if let Some(ref ml_pk_b64) = signature.ml_dsa_public_key {
                let verifier = match MeshMlDsaVerifier::from_base64(ml_pk_b64) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                verifier.verify(content, &signature.ml_dsa_signature)
            } else {
                false
            }
        } else {
            false
        }
    }

    fn verify_ed25519_explicit(&self, content: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
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

    pub fn has_ml_dsa(&self) -> bool {
        self.ml_dsa_signer
            .as_ref()
            .map(|s| s.has_signing_key())
            .unwrap_or(false)
    }

    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.ed25519_verifying_key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_signer_generate() {
        let signer = MeshMlDsaSigner::generate();
        assert!(signer.has_signing_key());
        assert!(signer.has_verifying_key());
    }

    #[test]
    fn test_ml_dsa_sign_verify() {
        let signer = MeshMlDsaSigner::generate();
        let message = b"test message for ML-DSA signing";

        let signature = signer.sign(message).expect("Signing failed");
        assert!(signer.verify(message, &signature));
    }

    #[test]
    fn test_ml_dsa_verify_fails_wrong_message() {
        let signer = MeshMlDsaSigner::generate();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = signer.sign(message).expect("Signing failed");
        assert!(!signer.verify(wrong_message, &signature));
    }

    #[test]
    fn test_key_sizes() {
        let ml_dsa_signer = MeshMlDsaSigner::generate();
        let message = b"test";

        let sig = ml_dsa_signer.sign(message).unwrap();
        assert_eq!(sig.len(), 2420);
    }
}
