//! ML-KEM-768 implementation using aws-lc-rs

use crate::kem::kem_trait::{KemError, KemSession};
use pqc::MlKem768 as PqcMlKem768;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct MlKem768PublicKey(pub Vec<u8>);

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SecretKey {
    #[zeroize(skip)]
    _marker: std::marker::PhantomData<()>,
    data: Vec<u8>,
}

impl MlKem768SecretKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            _marker: std::marker::PhantomData,
            data,
        }
    }
}

impl AsRef<[u8]> for MlKem768SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret {
    #[zeroize(skip)]
    _marker: std::marker::PhantomData<()>,
    data: Vec<u8>,
}

impl MlKem768SharedSecret {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            _marker: std::marker::PhantomData,
            data,
        }
    }
}

impl AsRef<[u8]> for MlKem768SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone, Debug)]
pub struct MlKem768;

impl KemSession for MlKem768 {
    type PublicKey = MlKem768PublicKey;
    type SecretKey = MlKem768SecretKey;
    type SharedSecret = MlKem768SharedSecret;

    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), KemError> {
        let (pk, sk) = PqcMlKem768::generate_keypair()
            .map_err(|e| KemError::KeyGenerationFailed(e.to_string()))?;

        Ok((
            MlKem768PublicKey(pk.to_vec()),
            MlKem768SecretKey::new(sk.to_vec()),
        ))
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Self::SharedSecret), KemError> {
        let pqc_pk =
            pqc::PublicKey::from_bytes(pk.as_ref()).map_err(|_| KemError::InvalidKeySize {
                expected: Self::PUBLIC_KEY_SIZE,
                actual: pk.as_ref().len(),
            })?;

        let (ct, ss) = PqcMlKem768::encapsulate(&pqc_pk)
            .map_err(|e| KemError::EncapsulationFailed(e.to_string()))?;

        Ok((ct.to_vec(), MlKem768SharedSecret::new(ss.to_vec())))
    }

    fn decapsulate(ct: &[u8], sk: &Self::SecretKey) -> Result<Self::SharedSecret, KemError> {
        if ct.len() != Self::CIPHERTEXT_SIZE {
            return Err(KemError::InvalidCiphertextSize {
                expected: Self::CIPHERTEXT_SIZE,
                actual: ct.len(),
            });
        }

        if sk.as_ref().len() != Self::SECRET_KEY_SIZE {
            return Err(KemError::InvalidKeySize {
                expected: Self::SECRET_KEY_SIZE,
                actual: sk.as_ref().len(),
            });
        }

        let pqc_sk =
            pqc::SecretKey::from_bytes(sk.as_ref()).map_err(|_| KemError::InvalidKeySize {
                expected: Self::SECRET_KEY_SIZE,
                actual: sk.as_ref().len(),
            })?;

        let pqc_ct =
            pqc::Ciphertext::from_bytes(ct).map_err(|_| KemError::InvalidCiphertextSize {
                expected: Self::CIPHERTEXT_SIZE,
                actual: ct.len(),
            })?;

        let ss = PqcMlKem768::decapsulate(&pqc_ct, &pqc_sk)
            .map_err(|e| KemError::DecapsulationFailed(e.to_string()))?;

        Ok(MlKem768SharedSecret::new(ss.to_vec()))
    }

    const PUBLIC_KEY_SIZE: usize = 1184;
    const SECRET_KEY_SIZE: usize = 2400;
    const CIPHERTEXT_SIZE: usize = 1088;
    const SHARED_SECRET_SIZE: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_session() -> Result<(), Box<dyn std::error::Error>> {
        let (pk, sk) = MlKem768::generate_keypair()?;

        assert_eq!(pk.as_ref().len(), MlKem768::PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_ref().len(), MlKem768::SECRET_KEY_SIZE);

        let (ct, ss_send) = MlKem768::encapsulate(&pk)?;

        assert_eq!(ct.len(), MlKem768::CIPHERTEXT_SIZE);
        assert_eq!(ss_send.as_ref().len(), MlKem768::SHARED_SECRET_SIZE);

        let ss_recv = MlKem768::decapsulate(&ct, &sk)?;

        assert_eq!(ss_send.as_ref(), ss_recv.as_ref());
        Ok(())
    }
}
