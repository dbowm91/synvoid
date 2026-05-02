//! Hybrid Ed25519 + ML-DSA-44 signature support for mesh messages.
//!
//! This module provides hybrid signature types that combine classical
//! Ed25519 signatures with post-quantum ML-DSA-44 signatures for
//! enhanced security against quantum adversaries.

use serde::{Deserialize, Serialize};

pub use crate::integrity::signing::{
    sign_ed25519, sign_ml_dsa, verify_ed25519, verify_ed25519_raw, verify_ml_dsa,
};

pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const ML_DSA_SIGNATURE_SIZE: usize = 2420;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519_signature: Vec<u8>,
    pub ml_dsa_signature: Vec<u8>,
    pub ed25519_public_key: String,
    pub ml_dsa_public_key: Option<String>,
}

impl HybridSignature {
    pub fn new(
        ed25519_sig: Vec<u8>,
        ml_dsa_sig: Vec<u8>,
        ed25519_public_key: String,
        ml_dsa_public_key: Option<String>,
    ) -> Self {
        Self {
            ed25519_signature: ed25519_sig,
            ml_dsa_signature: ml_dsa_sig,
            ed25519_public_key,
            ml_dsa_public_key,
        }
    }

    pub fn ed25519_only(ed25519_sig: Vec<u8>, ed25519_public_key: String) -> Self {
        Self {
            ed25519_signature: ed25519_sig,
            ml_dsa_signature: Vec::new(),
            ed25519_public_key,
            ml_dsa_public_key: None,
        }
    }

    pub fn has_ml_dsa(&self) -> bool {
        !self.ml_dsa_signature.is_empty() && self.ml_dsa_public_key.is_some()
    }

    pub fn serialized_size(&self) -> usize {
        4 + self.ed25519_signature.len()
            + 4
            + self.ml_dsa_signature.len()
            + 4
            + self.ed25519_public_key.len()
            + 4
            + self
                .ml_dsa_public_key
                .as_ref()
                .map(|s| s.len())
                .unwrap_or(0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.serialized_size());

        result.extend_from_slice(&(self.ed25519_signature.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.ed25519_signature);

        result.extend_from_slice(&(self.ml_dsa_signature.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.ml_dsa_signature);

        let ed_pk_bytes = self.ed25519_public_key.as_bytes();
        result.extend_from_slice(&(ed_pk_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(ed_pk_bytes);

        if let Some(ref ml_pk) = self.ml_dsa_public_key {
            let ml_pk_bytes = ml_pk.as_bytes();
            result.extend_from_slice(&(ml_pk_bytes.len() as u32).to_le_bytes());
            result.extend_from_slice(ml_pk_bytes);
        } else {
            result.extend_from_slice(&0u32.to_le_bytes());
        }

        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignatureError> {
        let mut offset = 0;

        if bytes.len() < offset + 4 {
            return Err(HybridSignatureError::InvalidFormat);
        }
        let ed25519_len =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if bytes.len() < offset + ed25519_len {
            return Err(HybridSignatureError::InvalidEd25519Signature);
        }
        let ed25519_sig = bytes[offset..offset + ed25519_len].to_vec();
        offset += ed25519_len;

        if bytes.len() < offset + 4 {
            return Err(HybridSignatureError::InvalidFormat);
        }
        let ml_dsa_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if bytes.len() < offset + ml_dsa_len {
            return Err(HybridSignatureError::InvalidMlDsaSignature);
        }
        let ml_dsa_sig = bytes[offset..offset + ml_dsa_len].to_vec();
        offset += ml_dsa_len;

        if bytes.len() < offset + 4 {
            return Err(HybridSignatureError::InvalidFormat);
        }
        let ed_pk_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if bytes.len() < offset + ed_pk_len {
            return Err(HybridSignatureError::InvalidPublicKey);
        }
        let ed25519_public_key = String::from_utf8(bytes[offset..offset + ed_pk_len].to_vec())
            .map_err(|_| HybridSignatureError::InvalidPublicKey)?;
        offset += ed_pk_len;

        let ml_dsa_public_key = if bytes.len() >= offset + 4 {
            let ml_pk_len =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if ml_pk_len > 0 && bytes.len() >= offset + ml_pk_len {
                let s = String::from_utf8(bytes[offset..offset + ml_pk_len].to_vec())
                    .map_err(|_| HybridSignatureError::InvalidPublicKey)?;
                Some(s)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            ed25519_signature: ed25519_sig,
            ml_dsa_signature: ml_dsa_sig,
            ed25519_public_key,
            ml_dsa_public_key,
        })
    }
}

#[derive(Debug, Clone)]
pub enum HybridSignatureError {
    InvalidFormat,
    InvalidEd25519Signature,
    InvalidMlDsaSignature,
    InvalidPublicKey,
    Ed25519VerificationFailed,
    MlDsaVerificationFailed,
    EmptySignature,
}

impl std::fmt::Display for HybridSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HybridSignatureError::InvalidFormat => write!(f, "Invalid hybrid signature format"),
            HybridSignatureError::InvalidEd25519Signature => {
                write!(f, "Invalid Ed25519 signature length")
            }
            HybridSignatureError::InvalidMlDsaSignature => {
                write!(f, "Invalid ML-DSA signature length")
            }
            HybridSignatureError::InvalidPublicKey => write!(f, "Invalid public key"),
            HybridSignatureError::Ed25519VerificationFailed => {
                write!(f, "Ed25519 signature verification failed")
            }
            HybridSignatureError::MlDsaVerificationFailed => {
                write!(f, "ML-DSA signature verification failed")
            }
            HybridSignatureError::EmptySignature => write!(f, "Empty signature"),
        }
    }
}

impl std::error::Error for HybridSignatureError {}

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
