//! ML-DSA (FIPS 204) Digital Signature Algorithm
//!
//! Implements ML-DSA-44 for post-quantum secure digital signatures using libcrux.
//!
//! ## Context Parameter
//! The `context` parameter in sign/verify is used for domain separation as per FIPS 204.
//! An empty context is used here for basic signature/verification without additional
//! domain separation. For applications requiring context separation (e.g., signing in
//! different contexts), pass a non-empty byte slice.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use libcrux_ml_dsa::ml_dsa_44::{
    self, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
    #[error("Invalid signature size: expected {expected}, got {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),
}

const KEY_GEN_RANDOMNESS: usize = 32;
const SIGNING_KEY_SIZE: usize = 2560;
const VERIFICATION_KEY_SIZE: usize = 1312;
const SIGNATURE_SIZE: usize = 2420;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SigningKey {
    #[zeroize(skip)]
    bytes: Vec<u8>,
}

impl SigningKey {
    pub const SIZE: usize = SIGNING_KEY_SIZE;

    pub fn generate() -> Result<(SigningKey, VerifyingKey), SignatureError> {
        let mut randomness = [0u8; KEY_GEN_RANDOMNESS];
        OsRng.fill_bytes(&mut randomness);

        let keypair = ml_dsa_44::generate_key_pair(randomness);

        let signing_bytes = keypair.signing_key.as_slice().to_vec();
        let verifying_bytes = keypair.verification_key.as_slice().to_vec();

        Ok((
            SigningKey {
                bytes: signing_bytes,
            },
            VerifyingKey {
                bytes: verifying_bytes,
            },
        ))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != Self::SIZE {
            return Err(SignatureError::InvalidKeySize {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.bytes)
    }

    pub fn from_base64(b64: &str) -> Result<Self, SignatureError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| SignatureError::Base64DecodeError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            bytes: self.bytes[SigningKey::SIZE - VerifyingKey::SIZE..].to_vec(),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct VerifyingKey {
    #[zeroize(skip)]
    bytes: Vec<u8>,
}

impl VerifyingKey {
    pub const SIZE: usize = VERIFICATION_KEY_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != Self::SIZE {
            return Err(SignatureError::InvalidKeySize {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.bytes)
    }

    pub fn from_base64(b64: &str) -> Result<Self, SignatureError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| SignatureError::Base64DecodeError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Signature {
    #[zeroize(skip)]
    bytes: Vec<u8>,
}

impl Signature {
    pub const SIZE: usize = SIGNATURE_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != Self::SIZE {
            return Err(SignatureError::InvalidSignatureSize {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.bytes)
    }

    pub fn from_base64(b64: &str) -> Result<Self, SignatureError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| SignatureError::Base64DecodeError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

pub struct MlDsa44;

impl MlDsa44 {
    pub const PUBLIC_KEY_SIZE: usize = VERIFICATION_KEY_SIZE;
    pub const SECRET_KEY_SIZE: usize = SIGNING_KEY_SIZE;
    pub const SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

    pub fn generate_keypair() -> Result<(VerifyingKey, SigningKey), SignatureError> {
        let (sk, vk) = SigningKey::generate()?;
        Ok((vk, sk))
    }

    pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Result<Signature, SignatureError> {
        let sk = MLDSA44SigningKey::new(signing_key.as_bytes().try_into().map_err(|_| {
            SignatureError::InvalidKeySize {
                expected: SIGNING_KEY_SIZE,
                actual: signing_key.as_bytes().len(),
            }
        })?);

        let context: &[u8] = &[];
        let mut randomness = [0u8; KEY_GEN_RANDOMNESS];
        OsRng.fill_bytes(&mut randomness);

        let sig = ml_dsa_44::sign(&sk, message, context, randomness)
            .map_err(|e| SignatureError::SigningFailed(format!("{:?}", e)))?;

        let sig_bytes = sig.as_slice().to_vec();

        Signature::from_bytes(&sig_bytes)
    }

    pub fn verify(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let vk =
            MLDSA44VerificationKey::new(verifying_key.as_bytes().try_into().map_err(|_| {
                SignatureError::InvalidKeySize {
                    expected: VERIFICATION_KEY_SIZE,
                    actual: verifying_key.as_bytes().len(),
                }
            })?);
        let sig = MLDSA44Signature::new(signature.as_bytes().try_into().map_err(|_| {
            SignatureError::InvalidSignatureSize {
                expected: SIGNATURE_SIZE,
                actual: signature.as_bytes().len(),
            }
        })?);

        let context: &[u8] = &[];

        ml_dsa_44::verify(&vk, message, context, &sig)
            .map_err(|e| SignatureError::VerificationFailed(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_signing() {
        let (verifying_key, signing_key) =
            MlDsa44::generate_keypair().expect("Key generation failed");

        assert_eq!(verifying_key.as_bytes().len(), MlDsa44::PUBLIC_KEY_SIZE);
        assert_eq!(signing_key.as_bytes().len(), MlDsa44::SECRET_KEY_SIZE);

        let message = b"test message";
        let signature = MlDsa44::sign(&signing_key, message).expect("Signing failed");

        assert_eq!(signature.as_bytes().len(), MlDsa44::SIGNATURE_SIZE);

        MlDsa44::verify(&verifying_key, message, &signature).expect("Verification failed");
    }

    #[test]
    fn test_ml_dsa_verify_fails_wrong_key() {
        let (_verifying_key, signing_key) =
            MlDsa44::generate_keypair().expect("Key generation failed");
        let (wrong_vk, _) = MlDsa44::generate_keypair().expect("Key generation failed");

        let message = b"test message";
        let signature = MlDsa44::sign(&signing_key, message).expect("Signing failed");

        let result = MlDsa44::verify(&wrong_vk, message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_serialization() {
        let (vk, sk) = MlDsa44::generate_keypair().expect("Key generation failed");

        let vk_b64 = vk.to_base64();
        let vk_recovered =
            VerifyingKey::from_base64(&vk_b64).expect("Failed to recover verifying key");
        assert_eq!(vk.as_bytes(), vk_recovered.as_bytes());

        let sk_b64 = sk.to_base64();
        let sk_recovered = SigningKey::from_base64(&sk_b64).expect("Failed to recover signing key");
        assert_eq!(sk.as_bytes(), sk_recovered.as_bytes());
    }
}
