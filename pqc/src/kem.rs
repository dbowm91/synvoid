//! ML-KEM-768 Key Encapsulation Mechanism
//!
//! Implements FIPS 203 ML-KEM-768 for post-quantum secure key exchange.

use aws_lc_rs::digest::SHA256_OUTPUT_LEN;
use aws_lc_rs::kem::{
    Ciphertext as AwsCiphertext, DecapsulationKey as AwsDecapsulationKey,
    EncapsulationKey as AwsEncapsulationKey, ML_KEM_1024, ML_KEM_768,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use thiserror::Error;

pub use crate::keys::{Ciphertext, KeySizeError, PublicKey, SecretKey, SharedSecret};

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
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),
}

pub struct MlKem768;

impl MlKem768 {
    pub const PUBLIC_KEY_SIZE: usize = 1184;
    pub const SECRET_KEY_SIZE: usize = 2400;
    pub const CIPHERTEXT_SIZE: usize = 1088;
    pub const SHARED_SECRET_SIZE: usize = SHA256_OUTPUT_LEN;

    pub fn generate_keypair() -> Result<(PublicKey, SecretKey), KemError> {
        let dk = AwsDecapsulationKey::generate(&ML_KEM_768)
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?;

        let ek = dk
            .encapsulation_key()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?;

        let pk_bytes = ek
            .key_bytes()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?
            .as_ref()
            .to_vec();

        let sk_bytes = dk
            .key_bytes()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?
            .as_ref()
            .to_vec();

        Ok((PublicKey(pk_bytes), SecretKey(sk_bytes)))
    }

    pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KemError> {
        if pk.0.len() != Self::PUBLIC_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::PUBLIC_KEY_SIZE,
                actual: pk.0.len(),
            });
        }

        let encapsulation_key = AwsEncapsulationKey::new(&ML_KEM_768, pk.0.as_ref())
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?;

        let (ciphertext, shared_secret) = encapsulation_key
            .encapsulate()
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?;

        let ct_bytes = ciphertext.as_ref().to_vec();
        let ss_bytes = shared_secret.as_ref().to_vec();

        Ok((Ciphertext(ct_bytes), SharedSecret(ss_bytes)))
    }

    pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, KemError> {
        if ct.0.len() != Self::CIPHERTEXT_SIZE {
            return Err(KemError::InvalidCiphertextSize {
                expected: Self::CIPHERTEXT_SIZE,
                actual: ct.0.len(),
            });
        }

        if sk.0.len() != Self::SECRET_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SECRET_KEY_SIZE,
                actual: sk.0.len(),
            });
        }

        let decapsulation_key = AwsDecapsulationKey::new(&ML_KEM_768, sk.0.as_ref())
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?;

        let ciphertext = AwsCiphertext::from(ct.0.as_ref());

        let shared_secret = decapsulation_key
            .decapsulate(ciphertext)
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?;

        Ok(SharedSecret(shared_secret.as_ref().to_vec()))
    }

    pub fn public_key_from_base64(b64: &str) -> Result<PublicKey, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(PublicKey(bytes))
    }

    pub fn secret_key_from_base64(b64: &str) -> Result<SecretKey, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::SECRET_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(SecretKey(bytes))
    }

    pub fn ciphertext_from_base64(b64: &str) -> Result<Ciphertext, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::CIPHERTEXT_SIZE {
            return Err(KemError::InvalidCiphertextSize {
                expected: Self::CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(Ciphertext(bytes))
    }

    pub fn shared_secret_from_base64(b64: &str) -> Result<SharedSecret, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::SHARED_SECRET_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SHARED_SECRET_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(SharedSecret(bytes))
    }
}

#[cfg(feature = "async")]
impl MlKem768 {
    pub async fn generate_keypair_async() -> Result<(PublicKey, SecretKey), KemError> {
        tokio::task::spawn_blocking(Self::generate_keypair)
            .await
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?
    }

    pub async fn encapsulate_async(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KemError> {
        let pk = pk.clone();
        tokio::task::spawn_blocking(move || Self::encapsulate(&pk))
            .await
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?
    }

    pub async fn decapsulate_async(
        ct: &Ciphertext,
        sk: &SecretKey,
    ) -> Result<SharedSecret, KemError> {
        let ct = ct.clone();
        let sk = sk.clone();
        tokio::task::spawn_blocking(move || Self::decapsulate(&ct, &sk))
            .await
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?
    }
}

pub struct MlKem1024;

impl MlKem1024 {
    pub const PUBLIC_KEY_SIZE: usize = 1568;
    pub const SECRET_KEY_SIZE: usize = 3168;
    pub const CIPHERTEXT_SIZE: usize = 1568;
    pub const SHARED_SECRET_SIZE: usize = SHA256_OUTPUT_LEN;

    pub fn generate_keypair() -> Result<(PublicKey, SecretKey), KemError> {
        let dk = AwsDecapsulationKey::generate(&ML_KEM_1024)
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?;

        let ek = dk
            .encapsulation_key()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?;

        let pk_bytes = ek
            .key_bytes()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?
            .as_ref()
            .to_vec();

        let sk_bytes = dk
            .key_bytes()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?
            .as_ref()
            .to_vec();

        Ok((PublicKey(pk_bytes), SecretKey(sk_bytes)))
    }

    pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KemError> {
        if pk.0.len() != Self::PUBLIC_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::PUBLIC_KEY_SIZE,
                actual: pk.0.len(),
            });
        }

        let encapsulation_key = AwsEncapsulationKey::new(&ML_KEM_1024, pk.0.as_ref())
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?;

        let (ciphertext, shared_secret) = encapsulation_key
            .encapsulate()
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?;

        let ct_bytes = ciphertext.as_ref().to_vec();
        let ss_bytes = shared_secret.as_ref().to_vec();

        Ok((Ciphertext(ct_bytes), SharedSecret(ss_bytes)))
    }

    pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, KemError> {
        if ct.0.len() != Self::CIPHERTEXT_SIZE {
            return Err(KemError::InvalidCiphertextSize {
                expected: Self::CIPHERTEXT_SIZE,
                actual: ct.0.len(),
            });
        }

        if sk.0.len() != Self::SECRET_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SECRET_KEY_SIZE,
                actual: sk.0.len(),
            });
        }

        let decapsulation_key = AwsDecapsulationKey::new(&ML_KEM_1024, sk.0.as_ref())
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?;

        let ciphertext = AwsCiphertext::from(ct.0.as_ref());

        let shared_secret = decapsulation_key
            .decapsulate(ciphertext)
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?;

        Ok(SharedSecret(shared_secret.as_ref().to_vec()))
    }

    pub fn public_key_from_base64(b64: &str) -> Result<PublicKey, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(PublicKey(bytes))
    }

    pub fn secret_key_from_base64(b64: &str) -> Result<SecretKey, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::SECRET_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(SecretKey(bytes))
    }

    pub fn ciphertext_from_base64(b64: &str) -> Result<Ciphertext, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::CIPHERTEXT_SIZE {
            return Err(KemError::InvalidCiphertextSize {
                expected: Self::CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(Ciphertext(bytes))
    }

    pub fn shared_secret_from_base64(b64: &str) -> Result<SharedSecret, KemError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| KemError::Base64DecodeError(e.to_string()))?;

        if bytes.len() != Self::SHARED_SECRET_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SHARED_SECRET_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(SharedSecret(bytes))
    }
}

#[cfg(feature = "async")]
impl MlKem1024 {
    pub async fn generate_keypair_async() -> Result<(PublicKey, SecretKey), KemError> {
        tokio::task::spawn_blocking(Self::generate_keypair)
            .await
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?
    }

    pub async fn encapsulate_async(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KemError> {
        let pk = pk.clone();
        tokio::task::spawn_blocking(move || Self::encapsulate(&pk))
            .await
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?
    }

    pub async fn decapsulate_async(
        ct: &Ciphertext,
        sk: &SecretKey,
    ) -> Result<SharedSecret, KemError> {
        let ct = ct.clone();
        let sk = sk.clone();
        tokio::task::spawn_blocking(move || Self::decapsulate(&ct, &sk))
            .await
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_key_sizes() {
        assert_eq!(MlKem768::PUBLIC_KEY_SIZE, 1184);
        assert_eq!(MlKem768::SECRET_KEY_SIZE, 2400);
        assert_eq!(MlKem768::CIPHERTEXT_SIZE, 1088);
        assert_eq!(MlKem768::SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_generate_encapsulate_decapsulate() {
        let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");

        assert_eq!(pk.0.len(), MlKem768::PUBLIC_KEY_SIZE);
        assert_eq!(sk.0.len(), MlKem768::SECRET_KEY_SIZE);

        let (ct, ss_send) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");

        assert_eq!(ct.0.len(), MlKem768::CIPHERTEXT_SIZE);
        assert_eq!(ss_send.0.len(), MlKem768::SHARED_SECRET_SIZE);

        let ss_recv = MlKem768::decapsulate(&ct, &sk).expect("Decapsulation failed");

        assert_eq!(ss_send.0.len(), ss_recv.0.len());
        assert!(ss_send.0.as_slice().ct_eq(ss_recv.0.as_slice()).unwrap_u8() == 1);
    }

    #[test]
    fn test_shared_secret_compare() {
        let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");
        let (ct, ss_send) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");
        let ss_recv = MlKem768::decapsulate(&ct, &sk).expect("Decapsulation failed");

        assert!(ss_send.compare(&ss_recv));

        let (_, sk2) = MlKem768::generate_keypair().expect("Key generation failed");
        let ss_wrong =
            MlKem768::decapsulate(&ct, &sk2).expect("Decapsulation with wrong key doesn't panic");
        assert!(!ss_send.compare(&ss_wrong));
    }

    #[test]
    fn test_base64_serialization() {
        let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");

        let pk_b64 = pk.to_base64();

        let pk_roundtrip =
            MlKem768::public_key_from_base64(&pk_b64).expect("PK from base64 failed");

        assert_eq!(pk.0, pk_roundtrip.0);

        let sk_b64 =
            SecretKey::from_base64(&sk.to_base64()).expect("SecretKey::from_base64 should work");
        assert_eq!(sk.0, sk_b64.0);
    }

    #[test]
    fn test_from_bytes() {
        let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");

        let pk_from = PublicKey::from_bytes(pk.as_bytes()).expect("PK from bytes failed");
        let sk_from = SecretKey::from_bytes(sk.as_bytes()).expect("SK from bytes failed");

        assert_eq!(pk.0, pk_from.0);
        assert_eq!(sk.0, sk_from.0);
    }

    #[test]
    fn test_invalid_key_size() {
        let invalid_pk = PublicKey(vec![0u8; 100]);
        let result = MlKem768::encapsulate(&invalid_pk);
        assert!(result.is_err());

        if let Err(KemError::InvalidKeySize { .. }) = result {
        } else {
            panic!("Expected InvalidKeySize error");
        }
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let (_, sk) = MlKem768::generate_keypair().expect("Key generation failed");
        let invalid_ct = Ciphertext(vec![0u8; 100]);

        let result = MlKem768::decapsulate(&invalid_ct, &sk);
        assert!(result.is_err());

        if let Err(KemError::InvalidCiphertextSize { .. }) = result {
        } else {
            panic!("Expected InvalidCiphertextSize error");
        }
    }

    #[test]
    fn test_mlkem1024_key_sizes() {
        assert_eq!(MlKem1024::PUBLIC_KEY_SIZE, 1568);
        assert_eq!(MlKem1024::SECRET_KEY_SIZE, 3168);
        assert_eq!(MlKem1024::CIPHERTEXT_SIZE, 1568);
        assert_eq!(MlKem1024::SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_mlkem1024_generate_encapsulate_decapsulate() {
        let (pk, sk) = MlKem1024::generate_keypair().expect("Key generation failed");

        assert_eq!(pk.0.len(), MlKem1024::PUBLIC_KEY_SIZE);
        assert_eq!(sk.0.len(), MlKem1024::SECRET_KEY_SIZE);

        let (ct, ss_send) = MlKem1024::encapsulate(&pk).expect("Encapsulation failed");

        assert_eq!(ct.0.len(), MlKem1024::CIPHERTEXT_SIZE);
        assert_eq!(ss_send.0.len(), MlKem1024::SHARED_SECRET_SIZE);

        let ss_recv = MlKem1024::decapsulate(&ct, &sk).expect("Decapsulation failed");

        assert_eq!(ss_send.0.len(), ss_recv.0.len());
        assert!(ss_send.0.as_slice().ct_eq(ss_recv.0.as_slice()).unwrap_u8() == 1);
    }

    #[test]
    fn test_mlkem1024_shared_secret_compare() {
        let (pk, sk) = MlKem1024::generate_keypair().expect("Key generation failed");
        let (ct, ss_send) = MlKem1024::encapsulate(&pk).expect("Encapsulation failed");
        let ss_recv = MlKem1024::decapsulate(&ct, &sk).expect("Decapsulation failed");

        assert!(ss_send.compare(&ss_recv));

        let (_, sk2) = MlKem1024::generate_keypair().expect("Key generation failed");
        let ss_wrong =
            MlKem1024::decapsulate(&ct, &sk2).expect("Decapsulation with wrong key doesn't panic");
        assert!(!ss_send.compare(&ss_wrong));
    }

    #[test]
    fn test_mlkem1024_base64_serialization() {
        let (pk, sk) = MlKem1024::generate_keypair().expect("Key generation failed");

        let pk_b64 = pk.to_base64();

        let pk_roundtrip =
            MlKem1024::public_key_from_base64(&pk_b64).expect("PK from base64 failed");

        assert_eq!(pk.0, pk_roundtrip.0);

        let sk_b64 =
            SecretKey::from_base64(&sk.to_base64()).expect("SecretKey::from_base64 should work");
        assert_eq!(sk.0, sk_b64.0);
    }
}
