use std::io::{self, Read, Write};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

pub type HmacSha3_256 = Hmac<Sha3_256>;

pub const HMAC_SIZE: usize = 32;
pub const SIGNED_MESSAGE_OVERHEAD: usize = 4 + HMAC_SIZE;

pub struct IpcSigner {
    key: [u8; 32],
}

impl IpcSigner {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    pub fn from_secret(secret: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    pub fn sign(&self, data: &[u8]) -> [u8; HMAC_SIZE] {
        let mut mac =
            HmacSha3_256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        let mut hmac_bytes = [0u8; HMAC_SIZE];
        hmac_bytes.copy_from_slice(&result.into_bytes());
        hmac_bytes
    }

    pub fn verify(&self, data: &[u8], expected_hmac: &[u8; HMAC_SIZE]) -> bool {
        let computed_hmac = self.sign(data);
        use subtle::ConstantTimeEq;
        computed_hmac.ct_eq(expected_hmac).into()
    }
}

pub struct SignedWriter<W> {
    inner: W,
    signer: Arc<IpcSigner>,
}

impl<W> SignedWriter<W> {
    pub fn new(inner: W, signer: Arc<IpcSigner>) -> Self {
        Self { inner, signer }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for SignedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let hmac = self.signer.sign(buf);
        self.inner.write_all(&hmac)?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct SignedReader<R> {
    inner: R,
}

impl<R> SignedReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for SignedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

pub struct SignedIpcMessage {
    pub payload: Vec<u8>,
    pub hmac: Option<[u8; HMAC_SIZE]>,
}

impl SignedIpcMessage {
    pub fn new(payload: Vec<u8>, hmac: Option<[u8; HMAC_SIZE]>) -> Self {
        Self { payload, hmac }
    }

    pub fn serialize_signed<T: serde::Serialize>(
        msg: &T,
        signer: &IpcSigner,
    ) -> io::Result<Vec<u8>> {
        let payload = crate::serialization::serialize(msg)?;

        let hmac = signer.sign(&payload);

        let mut result = Vec::with_capacity(4 + HMAC_SIZE + payload.len());
        let len = (HMAC_SIZE + payload.len()) as u32;
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&hmac);
        result.extend_from_slice(&payload);

        Ok(result)
    }

    pub fn deserialize_signed<T: serde::de::DeserializeOwned>(
        data: &[u8],
        signer: &IpcSigner,
    ) -> io::Result<T> {
        const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

        if data.len() < 4 + HMAC_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message too short",
            ));
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message size invalid",
            ));
        }
        if data.len() < 4 + len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message incomplete",
            ));
        }

        let hmac: [u8; HMAC_SIZE] = data[4..4 + HMAC_SIZE].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HMAC extraction failed: insufficient data",
            )
        })?;
        let payload = &data[4 + HMAC_SIZE..4 + HMAC_SIZE + (len - HMAC_SIZE)];

        if !signer.verify(payload, &hmac) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }

        crate::serialization::deserialize(payload)
    }
}

pub fn generate_session_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let data = b"test message";
        let hmac = signer.sign(data);

        assert!(signer.verify(data, &hmac));
        assert!(!signer.verify(b"different message", &hmac));
    }

    #[test]
    fn test_serialize_signed() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = vec![1u8, 2, 3, 4];

        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();
        let decoded: Vec<u8> = SignedIpcMessage::deserialize_signed(&signed, &signer).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_invalid_hmac() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = vec![1u8, 2, 3, 4];

        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();

        let mut tampered = signed.clone();
        tampered[5] ^= 0xFF;

        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&tampered, &signer);
        assert!(result.is_err());
    }
}
