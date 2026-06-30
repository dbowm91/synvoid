//! HTTP message signing implementation
//!
//! This module provides hybrid Ed25519+ML-DSA-44 based signing for HTTP messages.
//! The security model assumes:
//! - Client signs requests with their Ed25519+ML-DSA key (proving identity)
//! - Origin signs responses with its Ed25519+ML-DSA key (proving authenticity)
//! - X25519+ML-KEM is used for key exchange (shared secret derivation)

use base64::Engine;
use ed25519_dalek::{
    Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

use pqc::{
    MlDsa44, Signature as MldsaSignature, SigningKey as MldsaSigningKey,
    VerifyingKey as MldsaVerifyingKey,
};

use crate::protocol::{SESSION_ID_HEADER, SIG_HEADER_PREFIX};
use crate::{IntegrityHeader, SessionKey, SignedHttpMessage};

/// Sign a message using Ed25519
pub fn sign_ed25519(signing_key: &Ed25519SigningKey, message: &str) -> Vec<u8> {
    let signature = signing_key.sign(message.as_bytes());
    signature.to_bytes().to_vec()
}

/// Verify an Ed25519 signature
pub fn verify_ed25519(
    verifying_key: &Ed25519VerifyingKey,
    message: &str,
    signature: &[u8],
) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message.as_bytes(), &sig).is_ok()
}

/// Verify an Ed25519 signature from raw public key bytes
pub fn verify_ed25519_raw(public_key_bytes: &[u8], message: &str, signature: &[u8]) -> bool {
    if public_key_bytes.len() != 32 || signature.len() != 64 {
        return false;
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key_bytes);

    match Ed25519VerifyingKey::from_bytes(&key_bytes) {
        Ok(verifying_key) => verify_ed25519(&verifying_key, message, signature),
        Err(_) => false,
    }
}

pub fn sign_ml_dsa(signing_key: &MldsaSigningKey, message: &str) -> Vec<u8> {
    let sig = MlDsa44::sign(signing_key, message.as_bytes()).expect("ML-DSA signing failed");
    sig.as_bytes().to_vec()
}

pub fn verify_ml_dsa(verifying_key: &MldsaVerifyingKey, message: &str, signature: &[u8]) -> bool {
    let sig = match MldsaSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    MlDsa44::verify(verifying_key, message.as_bytes(), &sig).is_ok()
}

pub struct HttpMessageSigner {
    session_key: Arc<RwLock<Option<SessionKey>>>,
    ed25519_signing_key: Option<Ed25519SigningKey>,
    ed25519_verifying_key: Option<Ed25519VerifyingKey>,
    mldsa_signing_key: Option<MldsaSigningKey>,
    mldsa_verifying_key: Option<MldsaVerifyingKey>,
}

impl HttpMessageSigner {
    pub fn new() -> Self {
        Self {
            session_key: Arc::new(RwLock::new(None)),
            ed25519_signing_key: None,
            ed25519_verifying_key: None,
            mldsa_signing_key: None,
            mldsa_verifying_key: None,
        }
    }

    pub fn with_ed25519_keys(
        signing_key: Ed25519SigningKey,
        verifying_key: Ed25519VerifyingKey,
    ) -> Self {
        Self {
            session_key: Arc::new(RwLock::new(None)),
            ed25519_signing_key: Some(signing_key),
            ed25519_verifying_key: Some(verifying_key),
            mldsa_signing_key: None,
            mldsa_verifying_key: None,
        }
    }

    pub fn with_hybrid_keys(
        ed25519_signing_key: Ed25519SigningKey,
        ed25519_verifying_key: Ed25519VerifyingKey,
        mldsa_signing_key: MldsaSigningKey,
        mldsa_verifying_key: MldsaVerifyingKey,
    ) -> Self {
        Self {
            session_key: Arc::new(RwLock::new(None)),
            ed25519_signing_key: Some(ed25519_signing_key),
            ed25519_verifying_key: Some(ed25519_verifying_key),
            mldsa_signing_key: Some(mldsa_signing_key),
            mldsa_verifying_key: Some(mldsa_verifying_key),
        }
    }

    pub fn set_session(&mut self, session: SessionKey) {
        *self.session_key.write() = Some(session);
    }

    pub fn set_ed25519_signing_key(&mut self, key: Ed25519SigningKey) {
        self.ed25519_signing_key = Some(key);
    }

    pub fn set_ed25519_verifying_key(&mut self, key: Ed25519VerifyingKey) {
        self.ed25519_verifying_key = Some(key);
    }

    pub fn set_mldsa_signing_key(&mut self, key: MldsaSigningKey) {
        self.mldsa_signing_key = Some(key);
    }

    pub fn set_mldsa_verifying_key(&mut self, key: MldsaVerifyingKey) {
        self.mldsa_verifying_key = Some(key);
    }

    pub fn has_ml_dsa(&self) -> bool {
        self.mldsa_signing_key.is_some()
    }

    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Option<SignedHttpMessage> {
        let ed25519_key = self.ed25519_signing_key.as_ref()?;
        let mldsa_key = self.mldsa_signing_key.as_ref();

        let (session_id, key_id) = {
            let guard = self.session_key.read();
            let session = guard.as_ref()?;
            (session.session_id.clone(), session.key_id.clone())
        };

        let body_hash = body.map(|b| {
            let mut hasher = Sha256::new();
            hasher.update(b);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let integrity_header = IntegrityHeader::new(session_id, key_id);

        let mut msg = SignedHttpMessage {
            integrity_header: integrity_header.clone(),
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            query: query.map(String::from),
            headers: headers.clone(),
            body_hash,
            signature: String::new(),
            signed_at: chrono::Utc::now().timestamp(),
        };

        let message = msg.message_to_sign();

        let ed25519_sig = sign_ed25519(ed25519_key, &message);

        let combined_sig = if let Some(mldsa_key) = mldsa_key {
            let mldsa_sig = sign_ml_dsa(mldsa_key, &message);
            let mut combined = vec![0u8; 1];
            combined.push(0x01);
            combined.extend_from_slice(&ed25519_sig);
            combined.extend_from_slice(&mldsa_sig);
            combined
        } else {
            let mut combined = vec![0u8; 1];
            combined.push(0x00);
            combined.extend_from_slice(&ed25519_sig);
            combined
        };

        msg.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined_sig);

        Some(msg)
    }
    pub fn sign_response(
        &self,
        status: u16,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Option<SignedHttpMessage> {
        let ed25519_key = self.ed25519_signing_key.as_ref()?;
        let mldsa_key = self.mldsa_signing_key.as_ref();

        let (session_id, key_id) = {
            let guard = self.session_key.read();
            let session = guard.as_ref()?;
            (session.session_id.clone(), session.key_id.clone())
        };

        let body_hash = body.map(|b| {
            let mut hasher = Sha256::new();
            hasher.update(b);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let integrity_header = IntegrityHeader::new(session_id, key_id);

        let mut msg = SignedHttpMessage {
            integrity_header: integrity_header.clone(),
            method: Some(format!("{}", status)),
            path: None,
            query: None,
            headers: headers.clone(),
            body_hash,
            signature: String::new(),
            signed_at: chrono::Utc::now().timestamp(),
        };

        let message = msg.message_to_sign();

        let ed25519_sig = sign_ed25519(ed25519_key, &message);

        let combined_sig = if let Some(mldsa_key) = mldsa_key {
            let mldsa_sig = sign_ml_dsa(mldsa_key, &message);
            let mut combined = vec![0u8; 1];
            combined.push(0x01);
            combined.extend_from_slice(&ed25519_sig);
            combined.extend_from_slice(&mldsa_sig);
            combined
        } else {
            let mut combined = vec![0u8; 1];
            combined.push(0x00);
            combined.extend_from_slice(&ed25519_sig);
            combined
        };

        msg.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined_sig);

        Some(msg)
    }

    /// Verify a message signature using hybrid Ed25519+ML-DSA
    /// Returns true if either signature is valid (backward compatibility)
    pub fn verify_signature(&self, message: &str, signature: &[u8]) -> bool {
        if signature.is_empty() {
            return false;
        }

        let sig_type = signature[0];

        let (ed25519_sig, mldsa_sig) = if sig_type == 0x00 {
            if signature.len() < 65 {
                return false;
            }
            (&signature[1..65], None)
        } else if sig_type == 0x01 {
            if signature.len() < 65 + 2420 {
                return false;
            }
            (&signature[1..65], Some(&signature[65..65 + 2420]))
        } else {
            return false;
        };

        if let Some(ed25519_vk) = self.ed25519_verifying_key.as_ref() {
            if verify_ed25519(ed25519_vk, message, ed25519_sig) {
                return true;
            }
        }

        if let (Some(mldsa_vk), Some(mldsa_sig)) = (self.mldsa_verifying_key.as_ref(), mldsa_sig) {
            if verify_ml_dsa(mldsa_vk, message, mldsa_sig) {
                return true;
            }
        }

        false
    }

    pub fn has_session(&self) -> bool {
        self.session_key.read().is_some()
    }

    pub fn session_id(&self) -> Option<String> {
        self.session_key
            .read()
            .as_ref()
            .map(|s| s.session_id.clone())
    }
}

impl Default for HttpMessageSigner {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HttpMessageVerifier {
    session_keys: Arc<RwLock<HashMap<String, SessionKey>>>,
    client_ed25519_verifying_keys: Arc<RwLock<HashMap<String, Ed25519VerifyingKey>>>,
    client_mldsa_verifying_keys: Arc<RwLock<HashMap<String, MldsaVerifyingKey>>>,
}

impl HttpMessageVerifier {
    pub fn new() -> Self {
        Self {
            session_keys: Arc::new(RwLock::new(HashMap::new())),
            client_ed25519_verifying_keys: Arc::new(RwLock::new(HashMap::new())),
            client_mldsa_verifying_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_session(&self, session: SessionKey) {
        self.session_keys
            .write()
            .insert(session.session_id.clone(), session);
    }

    pub fn add_client_ed25519_key(&self, session_id: &str, verifying_key: Ed25519VerifyingKey) {
        self.client_ed25519_verifying_keys
            .write()
            .insert(session_id.to_string(), verifying_key);
    }

    pub fn add_client_mldsa_key(&self, session_id: &str, verifying_key: MldsaVerifyingKey) {
        self.client_mldsa_verifying_keys
            .write()
            .insert(session_id.to_string(), verifying_key);
    }

    pub fn remove_session(&self, session_id: &str) {
        self.session_keys.write().remove(session_id);
        self.client_ed25519_verifying_keys
            .write()
            .remove(session_id);
        self.client_mldsa_verifying_keys.write().remove(session_id);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_request(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        integrity_header: &IntegrityHeader,
        signature: &str,
    ) -> Result<bool, String> {
        let ed25519_verifying_key = {
            let keys = self.client_ed25519_verifying_keys.read();
            match keys.get(&integrity_header.session_id) {
                Some(k) => *k,
                None => return Err("No client Ed25519 key for session".to_string()),
            }
        };

        let mldsa_verifying_key = {
            let keys = self.client_mldsa_verifying_keys.read();
            keys.get(&integrity_header.session_id).cloned()
        };

        let session = {
            let keys = self.session_keys.read();
            match keys.get(&integrity_header.session_id) {
                Some(s) => s.clone(),
                None => return Err("Unknown session".to_string()),
            }
        };

        if session.is_expired() {
            return Err("Session expired".to_string());
        }

        let body_hash = body.map(|b| {
            let mut hasher = Sha256::new();
            hasher.update(b);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let msg = SignedHttpMessage {
            integrity_header: integrity_header.clone(),
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            query: query.map(String::from),
            headers: headers.clone(),
            body_hash,
            signature: String::new(),
            signed_at: chrono::Utc::now().timestamp(),
        };

        let message = msg.message_to_sign();
        let expected_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        let valid = if expected_sig.is_empty() {
            false
        } else {
            let sig_type = expected_sig[0];

            let (ed25519_sig, mldsa_sig) = if sig_type == 0x00 {
                if expected_sig.len() < 65 {
                    return Err("Invalid signature length".to_string());
                }
                (&expected_sig[1..65], None)
            } else if sig_type == 0x01 {
                if expected_sig.len() < 65 + 2420 {
                    return Err("Invalid signature length".to_string());
                }
                (&expected_sig[1..65], Some(&expected_sig[65..65 + 2420]))
            } else {
                return Err("Unknown signature type".to_string());
            };

            let ed25519_valid = verify_ed25519(&ed25519_verifying_key, &message, ed25519_sig);

            if ed25519_valid {
                return Ok(true);
            }

            if let (Some(mldsa_vk), Some(mldsa_sig)) = (mldsa_verifying_key.as_ref(), mldsa_sig) {
                if verify_ml_dsa(mldsa_vk, &message, mldsa_sig) {
                    return Ok(true);
                }
            }

            false
        };

        if valid {
            Ok(true)
        } else {
            Err("Signature mismatch".to_string())
        }
    }

    pub fn verify_response(
        &self,
        status: u16,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        integrity_header: &IntegrityHeader,
        signature: &str,
    ) -> Result<bool, String> {
        let ed25519_verifying_key = {
            let keys = self.client_ed25519_verifying_keys.read();
            match keys.get(&integrity_header.session_id) {
                Some(k) => *k,
                None => return Err("No client Ed25519 key for session".to_string()),
            }
        };

        let mldsa_verifying_key = {
            let keys = self.client_mldsa_verifying_keys.read();
            keys.get(&integrity_header.session_id).cloned()
        };

        let session = {
            let keys = self.session_keys.read();
            match keys.get(&integrity_header.session_id) {
                Some(s) => s.clone(),
                None => return Err("Unknown session".to_string()),
            }
        };

        if session.is_expired() {
            return Err("Session expired".to_string());
        }

        let body_hash = body.map(|b| {
            let mut hasher = Sha256::new();
            hasher.update(b);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let msg = SignedHttpMessage {
            integrity_header: integrity_header.clone(),
            method: Some(format!("{}", status)),
            path: None,
            query: None,
            headers: headers.clone(),
            body_hash,
            signature: String::new(),
            signed_at: chrono::Utc::now().timestamp(),
        };

        let message = msg.message_to_sign();
        let expected_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        let valid = if expected_sig.is_empty() {
            false
        } else {
            let sig_type = expected_sig[0];

            let (ed25519_sig, mldsa_sig) = if sig_type == 0x00 {
                if expected_sig.len() < 65 {
                    return Err("Invalid signature length".to_string());
                }
                (&expected_sig[1..65], None)
            } else if sig_type == 0x01 {
                if expected_sig.len() < 65 + 2420 {
                    return Err("Invalid signature length".to_string());
                }
                (&expected_sig[1..65], Some(&expected_sig[65..65 + 2420]))
            } else {
                return Err("Unknown signature type".to_string());
            };

            let ed25519_valid = verify_ed25519(&ed25519_verifying_key, &message, ed25519_sig);

            if ed25519_valid {
                return Ok(true);
            }

            if let (Some(mldsa_vk), Some(mldsa_sig)) = (mldsa_verifying_key.as_ref(), mldsa_sig) {
                if verify_ml_dsa(mldsa_vk, &message, mldsa_sig) {
                    return Ok(true);
                }
            }

            false
        };

        if valid {
            Ok(true)
        } else {
            Err("Signature mismatch".to_string())
        }
    }
}

impl Default for HttpMessageVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_integrity_headers(headers: &http::HeaderMap) -> Option<(IntegrityHeader, String)> {
    let session_id = headers.get(SESSION_ID_HEADER)?.to_str().ok()?.to_string();

    let sig_header = format!("{}{}", SIG_HEADER_PREFIX, "http");
    let signature = headers.get(sig_header.as_str())?.to_str().ok()?.to_string();

    let key_header = format!("{}{}", crate::KEY_HEADER_PREFIX, "session");
    let key_id = headers
        .get(key_header.as_str())
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| "default".to_string());

    let timestamp_header = format!("{}{}", crate::KEY_HEADER_PREFIX, "timestamp");
    let timestamp: i64 = headers
        .get(timestamp_header.as_str())
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    let nonce_header = format!("{}{}", crate::KEY_HEADER_PREFIX, "nonce");
    let nonce = headers
        .get(nonce_header.as_str())
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| "".to_string());

    let integrity_header = IntegrityHeader {
        session_id,
        key_id,
        timestamp,
        nonce,
    };

    Some((integrity_header, signature))
}

pub fn headers_to_map(headers: &http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_lowercase(), v.to_string()))
        })
        .collect()
}
