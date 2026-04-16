//! Key types for post-quantum cryptography
//!
//! Provides type-safe wrappers for ML-KEM keys with zeroize support.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    pub const SIZE: usize = 1184;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeySizeError> {
        if bytes.len() != Self::SIZE {
            return Err(KeySizeError {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        Ok(Self(URL_SAFE_NO_PAD.decode(b64)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub Vec<u8>);

impl SecretKey {
    pub const SIZE: usize = 2400;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeySizeError> {
        if bytes.len() != Self::SIZE {
            return Err(KeySizeError {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    #[cfg(test)]
    pub fn to_base64_test(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        Ok(Self(URL_SAFE_NO_PAD.decode(b64)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn public_key(&self) -> Result<PublicKey, String> {
        use aws_lc_rs::kem::{DecapsulationKey as AwsDecapsulationKey, ML_KEM_768};
        let dk = AwsDecapsulationKey::new(&ML_KEM_768, &self.0)
            .map_err(|e| format!("Failed to create decapsulation key: {}", e))?;
        let ek = dk
            .encapsulation_key()
            .map_err(|e| format!("Failed to get encapsulation key: {}", e))?;
        let pk_bytes = ek
            .key_bytes()
            .map_err(|e| format!("Failed to get public key bytes: {}", e))?
            .as_ref()
            .to_vec();
        Ok(PublicKey(pk_bytes))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ciphertext(pub Vec<u8>);

impl Ciphertext {
    pub const SIZE: usize = 1088;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeySizeError> {
        if bytes.len() != Self::SIZE {
            return Err(KeySizeError {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        Ok(Self(URL_SAFE_NO_PAD.decode(b64)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub Vec<u8>);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([... {} bytes ...])", self.0.len())
    }
}

impl SharedSecret {
    pub const SIZE: usize = 32;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeySizeError> {
        if bytes.len() != Self::SIZE {
            return Err(KeySizeError {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        Ok(Self(URL_SAFE_NO_PAD.decode(b64)?))
    }

    pub fn compare(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        let result = self.0.as_slice().ct_eq(other.0.as_slice());
        result.unwrap_u8() == 1
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<SharedSecret> for SharedSecret {
    fn as_ref(&self) -> &SharedSecret {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySizeError {
    pub expected: usize,
    pub actual: usize,
}

impl std::fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid key size: expected {}, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for KeySizeError {}
