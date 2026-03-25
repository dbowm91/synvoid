use std::collections::HashMap;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;

use crate::config::dns::{TsigAlgorithm, TsigKeyConfig};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Clone)]
pub struct TsigKey {
    pub name: String,
    pub secret: Vec<u8>,
    pub algorithm: TsigAlgorithm,
}

impl TsigKey {
    pub fn from_config(config: &TsigKeyConfig) -> Result<Self, String> {
        let secret = BASE64
            .decode(&config.secret_base64)
            .map_err(|e| format!("Invalid TSIG secret base64: {}", e))?;

        if secret.len() < config.algorithm.key_size() / 2 {
            return Err(format!(
                "TSIG secret too short for {}",
                config.algorithm.dns_algorithm_name()
            ));
        }

        Ok(Self {
            name: config.name.clone(),
            secret,
            algorithm: config.algorithm,
        })
    }
}

pub struct TsigVerifier {
    keys: Arc<RwLock<HashMap<String, TsigKey>>>,
}

impl TsigVerifier {
    pub fn new(keys_config: Vec<TsigKeyConfig>) -> Result<Self, String> {
        let mut keys = HashMap::new();

        for config in keys_config {
            let key = TsigKey::from_config(&config)?;
            keys.insert(key.name.clone(), key);
        }

        Ok(Self {
            keys: Arc::new(RwLock::new(keys)),
        })
    }

    pub fn add_key(&self, config: TsigKeyConfig) -> Result<(), String> {
        let key = TsigKey::from_config(&config)?;
        self.keys.write().insert(key.name.clone(), key);
        Ok(())
    }

    pub fn remove_key(&self, name: &str) -> Option<TsigKey> {
        self.keys.write().remove(name)
    }

    pub fn verify(
        &self,
        _tsig_record: &[u8],
        message: &[u8],
        original_mac: &[u8],
        key_name: &str,
        algorithm: u16,
        time_signed: u64,
        fudge: u16,
        tsig_error: u16,
        other_len: u16,
    ) -> Result<(), TsigError> {
        if tsig_error != 0 {
            return Err(TsigError::BadSignature);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let fudge_val = fudge as u64;
        let time_diff = time_signed.abs_diff(now);

        if time_diff > fudge_val {
            return Err(TsigError::TimeInvalid);
        }

        let keys = self.keys.read();
        let key = keys
            .get(key_name)
            .ok_or(TsigError::UnknownKey(key_name.to_string()))?;

        if key.algorithm.to_u16() != algorithm {
            return Err(TsigError::AlgorithmMismatch);
        }

        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(message);

        data_to_sign.extend_from_slice(key_name.as_bytes());
        data_to_sign.push(0);

        data_to_sign.extend_from_slice(&key.algorithm.to_u16().to_be_bytes());

        let time_bytes = time_signed.to_be_bytes();
        data_to_sign.extend_from_slice(&time_bytes);

        data_to_sign.extend_from_slice(&fudge.to_be_bytes());

        data_to_sign.extend_from_slice(&tsig_error.to_be_bytes());

        if other_len > 0 {
            data_to_sign.extend_from_slice(&other_len.to_be_bytes());
        }

        let computed_mac = match key.algorithm {
            TsigAlgorithm::HmacSha256 => {
                let mut mac =
                    HmacSha256::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha1 => {
                let mut mac =
                    HmacSha1::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha384 => {
                let mut mac =
                    HmacSha384::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha512 => {
                let mut mac =
                    HmacSha512::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
        };

        if computed_mac.len() != original_mac.len() {
            return Err(TsigError::MacMismatch {
                expected: computed_mac.len(),
                actual: original_mac.len(),
            });
        }

        let mut diff = 0u8;
        for (a, b) in computed_mac.iter().zip(original_mac.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            return Err(TsigError::MacVerificationFailed);
        }

        Ok(())
    }

    pub fn sign(
        &self,
        key_name: &str,
        message: &[u8],
        tsig_error: u16,
    ) -> Result<Vec<u8>, TsigError> {
        let keys = self.keys.read();
        let key = keys
            .get(key_name)
            .ok_or(TsigError::UnknownKey(key_name.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fudge: u16 = 300;

        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(message);

        data_to_sign.extend_from_slice(key_name.as_bytes());
        data_to_sign.push(0);

        data_to_sign.extend_from_slice(&key.algorithm.to_u16().to_be_bytes());

        let time_bytes = now.to_be_bytes();
        data_to_sign.extend_from_slice(&time_bytes);

        data_to_sign.extend_from_slice(&fudge.to_be_bytes());

        data_to_sign.extend_from_slice(&tsig_error.to_be_bytes());

        data_to_sign.extend_from_slice(&0u16.to_be_bytes());

        let mac = match key.algorithm {
            TsigAlgorithm::HmacSha256 => {
                let mut mac =
                    HmacSha256::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha1 => {
                let mut mac =
                    HmacSha1::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha384 => {
                let mut mac =
                    HmacSha384::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha512 => {
                let mut mac =
                    HmacSha512::new_from_slice(&key.secret).map_err(|_| TsigError::InvalidKey)?;
                mac.update(&data_to_sign);
                mac.finalize().into_bytes().to_vec()
            }
        };

        let mut tsig_rdata = Vec::new();
        tsig_rdata.extend_from_slice(key_name.as_bytes());
        tsig_rdata.push(0);
        tsig_rdata.extend_from_slice(&key.algorithm.to_u16().to_be_bytes());
        tsig_rdata.extend_from_slice(&fudge.to_be_bytes());
        tsig_rdata.extend_from_slice(&now.to_be_bytes());
        tsig_rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        tsig_rdata.extend_from_slice(&mac);
        tsig_rdata.extend_from_slice(&tsig_error.to_be_bytes());
        tsig_rdata.extend_from_slice(&0u16.to_be_bytes());

        Ok(tsig_rdata)
    }
}

impl TsigAlgorithm {
    pub fn dns_algorithm_name(&self) -> &'static str {
        match self {
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha1 => "hmac-sha1",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum TsigError {
    #[error("Unknown TSIG key: {0}")]
    UnknownKey(String),
    #[error("Invalid TSIG key")]
    InvalidKey,
    #[error("TSIG MAC verification failed")]
    MacVerificationFailed,
    #[error("TSIG MAC length mismatch: expected {expected}, got {actual}")]
    MacMismatch { expected: usize, actual: usize },
    #[error("TSIG time out of valid range")]
    TimeInvalid,
    #[error("TSIG error code indicates failure")]
    BadSignature,
    #[error("TSIG algorithm mismatch")]
    AlgorithmMismatch,
    #[error("TSIG parse error: {0}")]
    ParseError(String),
}

pub fn parse_tsig_from_query(query: &[u8], qd_end: usize) -> Option<TsigParseResult> {
    if query.len() < qd_end + 11 {
        return None;
    }

    let mut pos = qd_end;

    while pos + 10 <= query.len() {
        let name_len = query[pos];
        if name_len != 0 {
            while pos < query.len() && query[pos] != 0 {
                pos += 1 + query[pos] as usize;
            }
            if pos >= query.len() {
                return None;
            }
            pos += 1;
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        pos += 2;

        if qtype != 250 {
            let rdlen = u16::from_be_bytes([query[pos], query[pos + 1]]);
            pos += 2;
            pos += rdlen as usize;
            continue;
        }

        pos += 2;

        let mut key_name = String::new();
        let key_start = pos;
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if !key_name.is_empty() {
                key_name.push('.');
            }
            if pos + 1 + len > query.len() {
                return None;
            }
            key_name.push_str(&String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]));
            pos += 1 + len;
        }

        if pos + 14 > query.len() {
            return None;
        }

        let algorithm = u16::from_be_bytes([query[pos], query[pos + 1]]);
        pos += 2;

        let time_signed = u48_to_u64(&query[pos..pos + 6]);
        pos += 6;

        let fudge = u16::from_be_bytes([query[pos], query[pos + 1]]);
        pos += 2;

        let mac_len = u16::from_be_bytes([query[pos], query[pos + 1]]);
        pos += 2;

        if pos + mac_len as usize > query.len() {
            return None;
        }

        let mac = query[pos..pos + mac_len as usize].to_vec();
        pos += mac_len as usize;

        let tsig_error = u16::from_be_bytes([query[pos], query[pos + 1]]);
        pos += 2;

        let other_len = u16::from_be_bytes([query[pos], query[pos + 1]]);

        return Some(TsigParseResult {
            key_name,
            algorithm,
            time_signed,
            fudge,
            mac,
            tsig_error,
            other_len,
            original_offset: key_start,
        });
    }

    None
}

fn u48_to_u64(bytes: &[u8]) -> u64 {
    if bytes.len() < 6 {
        return 0;
    }
    ((bytes[0] as u64) << 40)
        | ((bytes[1] as u64) << 32)
        | ((bytes[2] as u64) << 24)
        | ((bytes[3] as u64) << 16)
        | ((bytes[4] as u64) << 8)
        | (bytes[5] as u64)
}

#[derive(Debug, Clone)]
pub struct TsigParseResult {
    pub key_name: String,
    pub algorithm: u16,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    pub tsig_error: u16,
    pub other_len: u16,
    pub original_offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsig_algorithm_u16() {
        assert_eq!(TsigAlgorithm::HmacSha256.to_u16(), 161);
        assert_eq!(TsigAlgorithm::HmacSha1.to_u16(), 249);
        assert_eq!(TsigAlgorithm::HmacSha384.to_u16(), 170);
        assert_eq!(TsigAlgorithm::HmacSha512.to_u16(), 172);
    }

    #[test]
    fn test_tsig_algorithm_from_u16() {
        assert_eq!(
            TsigAlgorithm::from_u16(161),
            Some(TsigAlgorithm::HmacSha256)
        );
        assert_eq!(TsigAlgorithm::from_u16(249), Some(TsigAlgorithm::HmacSha1));
        assert_eq!(
            TsigAlgorithm::from_u16(170),
            Some(TsigAlgorithm::HmacSha384)
        );
        assert_eq!(
            TsigAlgorithm::from_u16(172),
            Some(TsigAlgorithm::HmacSha512)
        );
        assert_eq!(TsigAlgorithm::from_u16(999), None);
    }

    #[test]
    fn test_tsig_algorithm_dns_name() {
        assert_eq!(
            TsigAlgorithm::HmacSha256.dns_algorithm_name(),
            "hmac-sha256"
        );
        assert_eq!(TsigAlgorithm::HmacSha1.dns_algorithm_name(), "hmac-sha1");
        assert_eq!(
            TsigAlgorithm::HmacSha384.dns_algorithm_name(),
            "hmac-sha384"
        );
        assert_eq!(
            TsigAlgorithm::HmacSha512.dns_algorithm_name(),
            "hmac-sha512"
        );
    }

    #[test]
    fn test_tsig_algorithm_key_size() {
        assert_eq!(TsigAlgorithm::HmacSha256.key_size(), 32);
        assert_eq!(TsigAlgorithm::HmacSha1.key_size(), 20);
        assert_eq!(TsigAlgorithm::HmacSha384.key_size(), 48);
        assert_eq!(TsigAlgorithm::HmacSha512.key_size(), 64);
    }

    #[test]
    fn test_tsig_key_from_config() {
        let config = TsigKeyConfig {
            name: "test-key".to_string(),
            secret_base64: "dGVzdC1zZWNyZXQtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0".to_string(),
            algorithm: TsigAlgorithm::HmacSha256,
        };

        let key = TsigKey::from_config(&config).unwrap();
        assert_eq!(key.name, "test-key");
        assert!(!key.secret.is_empty());
    }

    #[test]
    fn test_tsig_key_from_config_all_algorithms() {
        let algorithms = [
            TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha1,
            TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512,
        ];

        for algorithm in algorithms {
            let config = TsigKeyConfig {
                name: format!("test-key-{:?}", algorithm),
                secret_base64: "dGVzdC1zZWNyZXQtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2"
                    .to_string(),
                algorithm,
            };

            let key = TsigKey::from_config(&config);
            assert!(
                key.is_ok(),
                "Should be able to create key for {:?}",
                algorithm
            );
        }
    }

    #[test]
    fn test_tsig_verifier() {
        let config = TsigKeyConfig {
            name: "test-key".to_string(),
            secret_base64: "dGVzdC1zZWNyZXQtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0".to_string(),
            algorithm: TsigAlgorithm::HmacSha256,
        };

        let verifier = TsigVerifier::new(vec![config]).unwrap();
        assert!(verifier.remove_key("test-key").is_some());
    }

    #[test]
    fn test_tsig_verifier_add_remove_key() {
        let verifier = TsigVerifier::new(vec![]).unwrap();

        let config = TsigKeyConfig {
            name: "new-key".to_string(),
            secret_base64: "dGVzdC1zZWNyZXQtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0".to_string(),
            algorithm: TsigAlgorithm::HmacSha256,
        };

        assert!(verifier.add_key(config.clone()).is_ok());
        assert!(verifier.remove_key("new-key").is_some());
        assert!(verifier.remove_key("nonexistent").is_none());
    }
}
