//! Origin WAF Attestation Module
//!
//! This module provides mechanisms to verify that origin WAF nodes
//! are legitimate and authorized to participate in the integrity system.

use base64::Engine;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Signer, Verifier};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub struct AttestationSigner {
    signing_key: SigningKey,
}

impl AttestationSigner {
    pub fn new(secret_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret_key);
        Self { signing_key }
    }

    pub fn sign(&self, message: &str) -> String {
        let signature = self.signing_key.sign(message.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    pub fn verifying_key(&self) -> String {
        let pk = self.signing_key.verifying_key();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes())
    }
}

pub struct AttestationVerifier {
    verifying_key: VerifyingKey,
}

impl AttestationVerifier {
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Option<Self> {
        VerifyingKey::from_bytes(key_bytes)
            .ok()
            .map(|pk| Self { verifying_key: pk })
    }

    pub fn from_base64(key_b64: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key_b64)
            .ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&bytes);
        Self::from_bytes(&key_array)
    }

    pub fn verify(&self, message: &str, signature: &str) -> bool {
        let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature) {
            Ok(bytes) if bytes.len() == 64 => bytes,
            _ => return false,
        };

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);

        let signature = Signature::from_bytes(&sig_array);

        self.verifying_key
            .verify(message.as_bytes(), &signature)
            .is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginAttestation {
    pub mesh_id: String,
    pub node_id: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: Option<String>,
    pub signed_at: i64,
    pub expires_at: i64,
    pub signature: String,
    pub attested_by: String,
}

impl OriginAttestation {
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.expires_at
    }

    pub fn verify(&self, verifying_key: &str) -> bool {
        if self.is_expired() {
            return false;
        }

        let message = format!(
            "{}|{}|{}|{}|{}",
            self.mesh_id, self.node_id, self.ed25519_public_key, self.signed_at, self.expires_at
        );

        AttestationVerifier::from_base64(verifying_key)
            .map(|v| v.verify(&message, &self.signature))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub mesh_id: String,
    pub node_id: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: Option<String>,
    pub timestamp: i64,
    pub nonce: String,
}

impl AttestationRequest {
    pub fn new(mesh_id: String, node_id: String, ed25519_public_key: String) -> Self {
        let nonce =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        Self {
            mesh_id,
            node_id,
            ed25519_public_key,
            x25519_public_key: None,
            timestamp: Utc::now().timestamp(),
            nonce,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub mesh_id: String,
    pub node_id: String,
    pub ed25519_public_key: String,
    pub signed_at: i64,
    pub expires_at: i64,
    pub signature: String,
}

impl AttestationResponse {
    pub fn create(
        request: &AttestationRequest,
        signer: &AttestationSigner,
        validity_secs: i64,
    ) -> Self {
        let signed_at = Utc::now().timestamp();
        let expires_at = signed_at + validity_secs;

        let message = format!(
            "{}|{}|{}|{}|{}",
            request.mesh_id, request.node_id, request.ed25519_public_key, signed_at, expires_at
        );

        Self {
            mesh_id: request.mesh_id.clone(),
            node_id: request.node_id.clone(),
            ed25519_public_key: request.ed25519_public_key.clone(),
            signed_at,
            expires_at,
            signature: signer.sign(&message),
        }
    }

    pub fn to_attestation(&self, attested_by: String) -> OriginAttestation {
        OriginAttestation {
            mesh_id: self.mesh_id.clone(),
            node_id: self.node_id.clone(),
            ed25519_public_key: self.ed25519_public_key.clone(),
            x25519_public_key: None,
            signed_at: self.signed_at,
            expires_at: self.expires_at,
            signature: self.signature.clone(),
            attested_by,
        }
    }
}

pub struct AttestationRegistry {
    attestations: Arc<RwLock<HashMap<String, OriginAttestation>>>,
    trusted_keys: Arc<RwLock<HashMap<String, String>>>,
    max_attestations: usize,
}

impl AttestationRegistry {
    pub fn new(max_attestations: usize) -> Self {
        Self {
            attestations: Arc::new(RwLock::new(HashMap::new())),
            trusted_keys: Arc::new(RwLock::new(HashMap::new())),
            max_attestations,
        }
    }

    pub fn add_trusted_key(&self, global_node_id: String, verifying_key: String) {
        self.trusted_keys
            .write()
            .insert(global_node_id, verifying_key);
    }

    pub fn register_attestation(
        &self,
        attestation: OriginAttestation,
        global_node_id: &str,
    ) -> Result<(), String> {
        let verifying_key = {
            let guard = self.trusted_keys.read();
            match guard.get(global_node_id) {
                Some(k) => k.clone(),
                None => return Err("Unknown global node".to_string()),
            }
        };

        if !attestation.verify(&verifying_key) {
            return Err("Invalid attestation signature".to_string());
        }

        let mut attestations = self.attestations.write();

        if attestations.len() >= self.max_attestations {
            let expired: Vec<_> = attestations
                .iter()
                .filter(|(_, a)| a.is_expired())
                .map(|(k, _)| k.clone())
                .collect();

            if expired.is_empty() {
                return Err("Attestation registry full".to_string());
            }

            for k in expired.iter().take(100) {
                attestations.remove(k);
            }
        }

        let key = format!("{}:{}", attestation.mesh_id, attestation.node_id);
        attestations.insert(key, attestation);

        Ok(())
    }

    pub fn is_origin_registered(&self, mesh_id: &str, node_id: &str) -> bool {
        let key = format!("{}:{}", mesh_id, node_id);
        self.attestations
            .read()
            .get(&key)
            .map(|a| !a.is_expired())
            .unwrap_or(false)
    }

    pub fn get_origin_key(&self, mesh_id: &str, node_id: &str) -> Option<String> {
        let key = format!("{}:{}", mesh_id, node_id);
        self.attestations
            .read()
            .get(&key)
            .filter(|a| !a.is_expired())
            .map(|a| a.ed25519_public_key.clone())
    }

    pub fn get_origin_x25519_key(&self, mesh_id: &str, node_id: &str) -> Option<String> {
        let key = format!("{}:{}", mesh_id, node_id);
        self.attestations
            .read()
            .get(&key)
            .filter(|a| !a.is_expired())
            .and_then(|a| a.x25519_public_key.clone())
    }

    pub fn revoke_attestation(&self, mesh_id: &str, node_id: &str) -> bool {
        let key = format!("{}:{}", mesh_id, node_id);
        self.attestations.write().remove(&key).is_some()
    }

    pub fn cleanup_expired(&self) -> usize {
        let expired: Vec<String> = self
            .attestations
            .read()
            .iter()
            .filter(|(_, a)| a.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        let mut attestations = self.attestations.write();
        let count = expired.len();

        for k in expired {
            attestations.remove(&k);
        }

        count
    }

    pub fn get_all_attestations(&self) -> Vec<OriginAttestation> {
        self.attestations.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_flow() {
        let signing_key = [0u8; 32];
        let signer = AttestationSigner::new(signing_key);
        let verifying_key = signer.verifying_key();

        let request = AttestationRequest::new(
            "mesh-1".to_string(),
            "origin-1".to_string(),
            "test-ed25519-pubkey".to_string(),
        );

        let response = AttestationResponse::create(&request, &signer, 3600);

        let attestation = response.to_attestation("global-1".to_string());

        let registry = AttestationRegistry::new(1000);
        registry.add_trusted_key("global-1".to_string(), verifying_key);

        assert!(registry
            .register_attestation(attestation.clone(), "global-1")
            .is_ok());
        assert!(registry.is_origin_registered("mesh-1", "origin-1"));

        let key = registry.get_origin_key("mesh-1", "origin-1");
        assert!(key.is_some());
    }
}
