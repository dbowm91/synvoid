//! Canonical hybrid signature envelope (value type only).
//!
//! Copied verbatim from `synvoid-mesh/src/mesh/hybrid_signature.rs` minus the
//! `synvoid_integrity::signing` re-exports (those pull the `pqc` runtime and
//! must stay in `synvoid-mesh`). This crate owns the length-prefixed
//! `to_bytes`/`from_bytes` encoding; ML-DSA *verification* stays in
//! `synvoid-mesh` (`MeshMlDsaVerifier`, `CryptoVerificationPool`).

pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const ML_DSA_SIGNATURE_SIZE: usize = 2420;

/// Canonical hybrid signature envelope: Ed25519 (always) + ML-DSA-44 (optional).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        let ed25519_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| HybridSignatureError::InvalidFormat)?,
        ) as usize;
        offset += 4;

        if bytes.len() < offset + ed25519_len {
            return Err(HybridSignatureError::InvalidEd25519Signature);
        }
        let ed25519_sig = bytes[offset..offset + ed25519_len].to_vec();
        offset += ed25519_len;

        if bytes.len() < offset + 4 {
            return Err(HybridSignatureError::InvalidFormat);
        }
        let ml_dsa_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| HybridSignatureError::InvalidFormat)?,
        ) as usize;
        offset += 4;

        if bytes.len() < offset + ml_dsa_len {
            return Err(HybridSignatureError::InvalidMlDsaSignature);
        }
        let ml_dsa_sig = bytes[offset..offset + ml_dsa_len].to_vec();
        offset += ml_dsa_len;

        if bytes.len() < offset + 4 {
            return Err(HybridSignatureError::InvalidFormat);
        }
        let ed_pk_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| HybridSignatureError::InvalidFormat)?,
        ) as usize;
        offset += 4;

        if bytes.len() < offset + ed_pk_len {
            return Err(HybridSignatureError::InvalidPublicKey);
        }
        let ed25519_public_key = String::from_utf8(bytes[offset..offset + ed_pk_len].to_vec())
            .map_err(|_| HybridSignatureError::InvalidPublicKey)?;
        offset += ed_pk_len;

        let ml_dsa_public_key = if bytes.len() >= offset + 4 {
            let ml_pk_len = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| HybridSignatureError::InvalidFormat)?,
            ) as usize;
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
