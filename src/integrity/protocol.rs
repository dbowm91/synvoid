//! Protocol types for integrity verification
#![allow(unused_variables, dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::sync::Arc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use pqc::{
    Ciphertext, MlKem768, PublicKey as PqcPublicKey, SecretKey as PqcSecretKey, SharedSecret,
};

pub const KEY_HEADER_PREFIX: &str = "X-Integrity-Key-";
pub const SIG_HEADER_PREFIX: &str = "X-Integrity-Sig-";
pub const SESSION_ID_HEADER: &str = "X-Integrity-Session";
pub const KEY_EXCHANGE_HEADER: &str = "X-Integrity-Config";
pub const KEY_REQUEST_HEADER: &str = "X-Integrity-Key-Request";

#[derive(Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: Vec<u8>,
}

impl Ed25519Signer {
    pub fn new(secret_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key().as_bytes().to_vec();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn sign(&self, message: &str) -> String {
        let signature = self.signing_key.sign(message.as_bytes());
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    pub fn verifying_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.verifying_key)
    }
}

#[derive(Clone)]
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Option<Self> {
        VerifyingKey::from_bytes(key_bytes)
            .ok()
            .map(|pk| Self { verifying_key: pk })
    }

    pub fn from_base64(key_b64: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(key_b64).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&bytes);
        Self::from_bytes(&key_array)
    }

    pub fn verify(&self, message: &str, signature: &str) -> bool {
        let sig_bytes = match URL_SAFE_NO_PAD.decode(signature) {
            Ok(bytes) if bytes.len() == 64 => bytes,
            _ => return false,
        };
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        self.verifying_key
            .verify(message.as_bytes(), &signature)
            .is_ok()
    }
}

pub struct X25519KeyExchange {
    static_secret: StaticSecret,
}

impl X25519KeyExchange {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self {
            static_secret: StaticSecret::from(bytes),
        }
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            static_secret: StaticSecret::from(secret),
        }
    }

    pub fn public_key(&self) -> String {
        let pk = X25519PublicKey::from(&self.static_secret);
        URL_SAFE_NO_PAD.encode(pk.as_bytes())
    }

    pub fn agree(&self, their_public_key: &str) -> Option<[u8; 32]> {
        let pk_bytes = URL_SAFE_NO_PAD.decode(their_public_key).ok()?;
        if pk_bytes.len() != 32 {
            return None;
        }
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&pk_bytes);
        let their_pk = X25519PublicKey::from(pk_array);
        let shared_secret = self.static_secret.diffie_hellman(&their_pk);
        Some(*shared_secret.as_bytes())
    }

    pub fn into_static_secret(self) -> StaticSecret {
        self.static_secret
    }

    pub fn static_secret(&self) -> &StaticSecret {
        &self.static_secret
    }
}

pub fn derive_session_key(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(salt.len() + info.len() + shared_secret.len());
    combined.extend_from_slice(salt);
    combined.extend_from_slice(info);
    combined.extend_from_slice(shared_secret);

    let hash = Sha3_256::digest(&combined);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

pub fn combine_secrets(classical: &[u8], pq: &[u8]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(classical.len() + pq.len() + 2);
    combined.push(0x01);
    combined.extend_from_slice(classical);
    combined.push(0x02);
    combined.extend_from_slice(pq);

    let hash = Sha3_256::digest(&combined);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

pub fn ml_kem_public_key_from_base64(b64: &str) -> Option<PqcPublicKey> {
    let bytes = URL_SAFE_NO_PAD.decode(b64).ok()?;
    if bytes.len() != MlKem768::PUBLIC_KEY_SIZE {
        return None;
    }
    Some(PqcPublicKey(bytes))
}

pub fn ml_kem_encapsulate(client_pk: &PqcPublicKey) -> Result<(Ciphertext, Vec<u8>), String> {
    let (ct, ss) = MlKem768::encapsulate(client_pk).map_err(|e| e.to_string())?;
    Ok((ct, ss.0.clone()))
}

pub fn ml_kem_decapsulate(ciphertext_b64: &str, secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let ct = MlKem768::ciphertext_from_base64(ciphertext_b64).map_err(|e| e.to_string())?;
    let sk = PqcSecretKey(secret_key.to_vec());
    let ss = MlKem768::decapsulate(&ct, &sk).map_err(|e| e.to_string())?;
    Ok(ss.0.clone())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityHeader {
    pub session_id: String,
    pub key_id: String,
    pub timestamp: i64,
    pub nonce: String,
}

impl IntegrityHeader {
    pub fn new(session_id: String, key_id: String) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        hasher.update(rand::random::<[u8; 16]>());
        let nonce = URL_SAFE_NO_PAD.encode(hasher.finalize()[..12].to_vec());

        Self {
            session_id,
            key_id,
            timestamp: Utc::now().timestamp(),
            nonce,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHttpMessage {
    pub integrity_header: IntegrityHeader,
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub body_hash: Option<String>,
    pub signature: String,
    pub signed_at: i64,
}

impl SignedHttpMessage {
    pub fn verify_with_key(&self, verifying_key: &str) -> Result<bool, String> {
        let verifier = Ed25519Verifier::from_base64(verifying_key)
            .ok_or_else(|| "Invalid verifying key".to_string())?;
        let message = self.message_to_sign();
        Ok(verifier.verify(&message, &self.signature))
    }

    pub fn message_to_sign(&self) -> String {
        let mut parts = vec![
            self.integrity_header.session_id.clone(),
            self.integrity_header.key_id.clone(),
            self.integrity_header.timestamp.to_string(),
            self.integrity_header.nonce.clone(),
        ];

        if let Some(ref m) = self.method {
            parts.push(m.clone());
        }
        if let Some(ref p) = self.path {
            parts.push(p.clone());
        }
        if let Some(ref q) = self.query {
            parts.push(q.clone());
        }
        if let Some(ref h) = self.body_hash {
            parts.push(h.clone());
        }

        let mut sorted_headers: Vec<_> = self.headers.iter().collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in sorted_headers {
            parts.push(format!("{}:{}", k, v));
        }

        parts.join("|")
    }

    pub fn body_hash(&self) -> Option<&str> {
        self.body_hash.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    pub session_id: String,
    pub key_id: String,
    pub mesh_id: String,
    pub verifying_key: String,
    pub client_x25519_pubkey: Option<String>,
    pub derived_key: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl SessionKey {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn derive_key(&self) -> Option<[u8; 32]> {
        let key_b64 = self.derived_key.as_ref()?;
        let key_bytes = URL_SAFE_NO_PAD.decode(key_b64).ok()?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Some(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KeyExchangeMessage {
    #[serde(rename = "key_request")]
    KeyRequest {
        mesh_id: String,
        client_x25519_pubkey: String,
        client_ml_kem_pubkey: Option<String>,
        nonce: String,
        timestamp: i64,
    },
    #[serde(rename = "key_offer")]
    KeyOffer {
        session_id: String,
        key_id: String,
        mesh_id: String,
        server_x25519_pubkey: String,
        server_ml_kem_pubkey: Option<String>,
        server_ml_kem_ciphertext: Option<String>,
        server_ed25519_pubkey: String,
        expires_at: i64,
        nonce: String,
        signature: String,
    },
    #[serde(rename = "key_accept")]
    KeyAccept {
        session_id: String,
        key_id: String,
        client_x25519_pubkey: String,
        client_ml_kem_pubkey: Option<String>,
        nonce: String,
        signature: String,
    },
    #[serde(rename = "key_confirm")]
    KeyConfirm {
        session_id: String,
        client_x25519_pubkey: String,
        signature: String,
    },
    #[serde(rename = "key_complete")]
    KeyComplete {
        session_id: String,
        signature: String,
    },
    #[serde(rename = "key_error")]
    KeyError { session_id: String, error: String },
}

impl KeyExchangeMessage {
    pub fn key_request(
        mesh_id: String,
        client_x25519_pubkey: String,
        client_ml_kem_pubkey: Option<String>,
    ) -> Self {
        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        Self::KeyRequest {
            mesh_id,
            client_x25519_pubkey,
            client_ml_kem_pubkey,
            nonce,
            timestamp: Utc::now().timestamp(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum MlKemVariant {
    #[default]
    MlKem768,
    MlKem1024,
}

pub struct SessionKeyManager {
    sessions: Arc<RwLock<HashMap<String, SessionKeyData>>>,
    ed25519_signer: Ed25519Signer,
    ml_kem_public_key: Option<PqcPublicKey>,
    ml_kem_secret_key: Option<PqcSecretKey>,
    ml_kem_variant: MlKemVariant,
    max_sessions: usize,
    ttl_secs: u64,
}

struct SessionKeyData {
    session: SessionKey,
    x25519_secret: StaticSecret,
    ml_kem_secret: Option<PqcSecretKey>,
    ml_kem_ciphertext: Option<Ciphertext>,
}

impl SessionKeyManager {
    pub fn new(ed25519_signing_key: [u8; 32], ttl_secs: u64, max_sessions: usize) -> Self {
        Self::with_ml_kem_variant(
            ed25519_signing_key,
            ttl_secs,
            max_sessions,
            MlKemVariant::default(),
        )
    }

    pub fn with_ml_kem_variant(
        ed25519_signing_key: [u8; 32],
        ttl_secs: u64,
        max_sessions: usize,
        variant: MlKemVariant,
    ) -> Self {
        let (ml_kem_public_key, ml_kem_secret_key) = match variant {
            MlKemVariant::MlKem768 => match MlKem768::generate_keypair() {
                Ok((pk, sk)) => (Some(pk), Some(sk)),
                Err(e) => {
                    tracing::warn!("Failed to generate ML-KEM-768 keypair: {}", e);
                    (None, None)
                }
            },
            MlKemVariant::MlKem1024 => match pqc::MlKem1024::generate_keypair() {
                Ok((pk, sk)) => (Some(pk), Some(sk)),
                Err(e) => {
                    tracing::warn!("Failed to generate ML-KEM-1024 keypair: {}", e);
                    (None, None)
                }
            },
        };

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ed25519_signer: Ed25519Signer::new(ed25519_signing_key),
            ml_kem_public_key,
            ml_kem_secret_key,
            ml_kem_variant: variant,
            max_sessions,
            ttl_secs,
        }
    }

    pub fn server_verifying_key(&self) -> String {
        self.ed25519_signer.verifying_key()
    }

    pub fn ml_kem_variant(&self) -> MlKemVariant {
        self.ml_kem_variant
    }

    pub fn ml_kem_public_key(&self) -> Option<String> {
        self.ml_kem_public_key
            .as_ref()
            .map(|pk| URL_SAFE_NO_PAD.encode(pk.as_bytes()))
    }

    pub fn encapsulate_for_client(&self, client_ml_kem_pubkey: &str) -> Option<(String, Vec<u8>)> {
        match self.ml_kem_variant {
            MlKemVariant::MlKem768 => {
                let client_pk = ml_kem_public_key_from_base64(client_ml_kem_pubkey)?;
                let (ct, ss) = MlKem768::encapsulate(&client_pk).ok()?;
                Some((ct.to_base64(), ss.0.clone()))
            }
            MlKemVariant::MlKem1024 => {
                let client_pk =
                    pqc::MlKem1024::public_key_from_base64(client_ml_kem_pubkey).ok()?;
                let (ct, ss) = pqc::MlKem1024::encapsulate(&client_pk).ok()?;
                Some((ct.to_base64(), ss.0.clone()))
            }
        }
    }

    pub fn generate_key_exchange(
        &self,
        mesh_id: String,
        client_x25519_pubkey: String,
        client_ml_kem_pubkey: Option<String>,
    ) -> KeyExchangeMessage {
        let session_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
        let key_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());

        let server_kex = X25519KeyExchange::generate();
        let server_x25519_pubkey = server_kex.public_key();

        let (server_ml_kem_pubkey, server_ml_kem_ciphertext, ml_kem_secret) =
            if let Some(ref client_pk_b64) = client_ml_kem_pubkey {
                match self.encapsulate_for_client(client_pk_b64) {
                    Some((ct, ss)) => (self.ml_kem_public_key(), Some(ct), Some(ss)),
                    None => {
                        tracing::warn!("ML-KEM encapsulation failed, falling back to X25519 only");
                        (None, None, None)
                    }
                }
            } else {
                (None, None, None)
            };

        let expires_at = Utc::now() + chrono::Duration::seconds(self.ttl_secs as i64);

        let message = format!(
            "{}|{}|{}|{}|{}|{}",
            session_id,
            key_id,
            mesh_id,
            server_x25519_pubkey,
            expires_at.timestamp(),
            nonce
        );

        let signature = self.ed25519_signer.sign(&message);

        let session = SessionKey {
            session_id: session_id.clone(),
            key_id: key_id.clone(),
            mesh_id: mesh_id.clone(),
            verifying_key: self.ed25519_signer.verifying_key(),
            client_x25519_pubkey: Some(client_x25519_pubkey),
            derived_key: None,
            expires_at,
            created_at: Utc::now(),
        };

        let x25519_secret = server_kex.into_static_secret();

        {
            let mut sessions = self.sessions.write();
            if sessions.len() >= self.max_sessions {
                let to_remove: Vec<_> = sessions
                    .iter()
                    .filter(|(_, s)| s.session.is_expired())
                    .map(|(k, _)| k.clone())
                    .take(100)
                    .collect();
                for k in to_remove {
                    sessions.remove(&k);
                }
            }
            sessions.insert(
                session_id.clone(),
                SessionKeyData {
                    session,
                    x25519_secret,
                    ml_kem_secret: ml_kem_secret.map(|ss| PqcSecretKey(ss)),
                    ml_kem_ciphertext: server_ml_kem_ciphertext
                        .as_ref()
                        .and_then(|ct| MlKem768::ciphertext_from_base64(ct).ok()),
                },
            );
        }

        KeyExchangeMessage::KeyOffer {
            session_id,
            key_id,
            mesh_id,
            server_x25519_pubkey,
            server_ml_kem_pubkey,
            server_ml_kem_ciphertext,
            server_ed25519_pubkey: self.ed25519_signer.verifying_key(),
            expires_at: expires_at.timestamp(),
            nonce,
            signature,
        }
    }

    pub fn confirm_key(
        &self,
        session_id: &str,
        client_x25519_pubkey: &str,
    ) -> Option<KeyExchangeMessage> {
        let client_pk_bytes = URL_SAFE_NO_PAD.decode(client_x25519_pubkey).ok()?;
        if client_pk_bytes.len() != 32 {
            return Some(KeyExchangeMessage::KeyError {
                session_id: session_id.to_string(),
                error: "Invalid client public key".to_string(),
            });
        }

        let mut client_pk_array = [0u8; 32];
        client_pk_array.copy_from_slice(&client_pk_bytes);

        let derived_key = {
            let mut sessions = self.sessions.write();
            let data = sessions.get_mut(session_id)?;

            if data.session.is_expired() {
                return Some(KeyExchangeMessage::KeyError {
                    session_id: session_id.to_string(),
                    error: "Session expired".to_string(),
                });
            }

            let client_pk = X25519PublicKey::from(client_pk_array);
            let x25519_shared = data.x25519_secret.diffie_hellman(&client_pk);

            let key = if let (Some(ref ml_kem_secret), Some(ref ml_kem_ct)) =
                (&data.ml_kem_secret, &data.ml_kem_ciphertext)
            {
                let ml_kem_shared = MlKem768::decapsulate(ml_kem_ct, ml_kem_secret)
                    .unwrap_or_else(|_| SharedSecret(vec![]));
                combine_secrets(x25519_shared.as_bytes(), &ml_kem_shared.0)
            } else {
                derive_session_key(
                    x25519_shared.as_bytes(),
                    b"integrity-session",
                    b"waf-integrity",
                )
            };

            key
        };

        {
            let mut sessions = self.sessions.write();
            let data = sessions.get_mut(session_id)?;
            data.session.client_x25519_pubkey = Some(client_x25519_pubkey.to_string());
            data.session.derived_key = Some(URL_SAFE_NO_PAD.encode(derived_key));
        }

        let message = format!("{}|{}|accepted", session_id, client_x25519_pubkey);
        let signature = self.ed25519_signer.sign(&message);

        Some(KeyExchangeMessage::KeyComplete {
            session_id: session_id.to_string(),
            signature,
        })
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionKey> {
        let guard = self.sessions.read();
        guard.get(session_id).map(|data| data.session.clone())
    }

    pub fn get_session_with_key(&self, session_id: &str) -> Option<SessionKey> {
        self.get_session(session_id)
    }

    pub fn remove_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }

    pub fn verifying_key_base64(&self) -> String {
        self.ed25519_signer.verifying_key()
    }
}

pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_signing_verification() {
        let signing_key = generate_random_key();
        let signer = Ed25519Signer::new(signing_key);
        let verifying_key = signer.verifying_key();

        let session_id = "test-session".to_string();
        let key_id = "test-key".to_string();

        let header = IntegrityHeader::new(session_id, key_id);

        let msg = SignedHttpMessage {
            integrity_header: header,
            method: Some("GET".to_string()),
            path: Some("/test".to_string()),
            query: Some("foo=bar".to_string()),
            headers: HashMap::new(),
            body_hash: None,
            signature: String::new(),
            signed_at: Utc::now().timestamp(),
        };

        let message = msg.message_to_sign();
        let signature = signer.sign(&message);

        let verifier = Ed25519Verifier::from_base64(&verifying_key).unwrap();
        assert!(verifier.verify(&message, &signature));
    }

    #[test]
    fn test_x25519_key_exchange() {
        let client = X25519KeyExchange::generate();
        let server = X25519KeyExchange::generate();

        let client_pubkey = client.public_key();
        let server_pubkey = server.public_key();

        let client_shared = client.agree(&server_pubkey).unwrap();
        let server_shared = server.agree(&client_pubkey).unwrap();

        assert_eq!(client_shared, server_shared);
    }
}

#[cfg(feature = "origin_key_exchange")]
pub mod origin_key_exchange {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OriginSignedSessionKey {
        pub session_id: String,
        pub key_id: String,
        pub mesh_id: String,
        pub server_x25519_pubkey: String,
        pub origin_mesh_id: String,
        pub origin_ed25519_pubkey: String,
        pub origin_signature: String,
        pub expires_at: i64,
        pub nonce: String,
        pub global_signature: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PendingOriginSession {
        pub session_id: String,
        pub key_id: String,
        pub mesh_id: String,
        pub origin_mesh_id: String,
        pub origin_ed25519_pubkey: String,
        pub server_x25519_pubkey: String,
        pub client_x25519_pubkey: Option<String>,
        pub expires_at: DateTime<Utc>,
        pub created_at: DateTime<Utc>,
        pub origin_signature: Option<String>,
    }

    pub struct OriginKeyExchangeManager {
        sessions: Arc<RwLock<HashMap<String, OriginSessionData>>>,
        global_ed25519_signer: Ed25519Signer,
        max_sessions: usize,
        ttl_secs: u64,
    }

    struct OriginSessionData {
        session: PendingOriginSession,
        x25519_secret: StaticSecret,
    }

    impl OriginKeyExchangeManager {
        pub fn new(
            global_ed25519_signing_key: [u8; 32],
            ttl_secs: u64,
            max_sessions: usize,
        ) -> Self {
            Self {
                sessions: Arc::new(RwLock::new(HashMap::new())),
                global_ed25519_signer: Ed25519Signer::new(global_ed25519_signing_key),
                max_sessions,
                ttl_secs,
            }
        }

        pub fn global_verifying_key(&self) -> String {
            self.global_ed25519_signer.verifying_key()
        }

        pub fn create_pending_session(
            &self,
            mesh_id: String,
            client_x25519_pubkey: String,
            origin_mesh_id: String,
            origin_ed25519_pubkey: String,
        ) -> (String, String, PendingOriginSession) {
            let session_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
            let key_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());

            let server_kex = X25519KeyExchange::generate();
            let server_x25519_pubkey = server_kex.public_key();

            let expires_at = Utc::now() + chrono::Duration::seconds(self.ttl_secs as i64);

            let session = PendingOriginSession {
                session_id: session_id.clone(),
                key_id: key_id.clone(),
                mesh_id: mesh_id.clone(),
                origin_mesh_id: origin_mesh_id.clone(),
                origin_ed25519_pubkey: origin_ed25519_pubkey.clone(),
                server_x25519_pubkey: server_x25519_pubkey.clone(),
                client_x25519_pubkey: Some(client_x25519_pubkey),
                expires_at,
                created_at: Utc::now(),
                origin_signature: None,
            };

            let x25519_secret = server_kex.into_static_secret();

            {
                let mut sessions = self.sessions.write();
                if sessions.len() >= self.max_sessions {
                    let to_remove: Vec<_> = sessions
                        .iter()
                        .filter(|(_, s)| s.session.is_expired())
                        .map(|(k, _)| k.clone())
                        .take(100)
                        .collect();
                    for k in to_remove {
                        sessions.remove(&k);
                    }
                }
                sessions.insert(
                    session_id.clone(),
                    OriginSessionData {
                        session: session.clone(),
                        x25519_secret,
                    },
                );
            }

            (session_id.clone(), server_x25519_pubkey.clone(), session)
        }

        pub fn complete_with_origin_signature(
            &self,
            session_id: &str,
            origin_signature: String,
            client_x25519_pubkey: &str,
        ) -> Option<OriginSignedSessionKey> {
            let client_pk_bytes = URL_SAFE_NO_PAD.decode(client_x25519_pubkey).ok()?;
            if client_pk_bytes.len() != 32 {
                return None;
            }

            let mut client_pk_array = [0u8; 32];
            client_pk_array.copy_from_slice(&client_pk_bytes);

            let session_data = {
                let mut sessions = self.sessions.write();
                let data = sessions.get_mut(session_id)?;

                if data.session.is_expired() {
                    return None;
                }

                data.session.client_x25519_pubkey = Some(client_x25519_pubkey.to_string());
                data.session.origin_signature = Some(origin_signature.clone());

                data.session.clone()
            };

            let _derived_key = {
                let sessions = self.sessions.read();
                let data = sessions.get(session_id)?;
                let client_pk = X25519PublicKey::from(client_pk_array);
                let shared_secret = data.x25519_secret.diffie_hellman(&client_pk);
                derive_session_key(
                    shared_secret.as_bytes(),
                    b"origin-integrity-session",
                    b"waf-origin-integrity",
                )
            };

            let sign_message = format!(
                "{}|{}|{}|{}|{}",
                session_data.session_id,
                session_data.key_id,
                session_data.mesh_id,
                session_data.server_x25519_pubkey,
                session_data.expires_at.timestamp()
            );
            let global_signature = self.global_ed25519_signer.sign(&sign_message);

            Some(OriginSignedSessionKey {
                session_id: session_data.session_id,
                key_id: session_data.key_id,
                mesh_id: session_data.mesh_id,
                server_x25519_pubkey: session_data.server_x25519_pubkey,
                origin_mesh_id: session_data.origin_mesh_id,
                origin_ed25519_pubkey: session_data.origin_ed25519_pubkey,
                origin_signature,
                expires_at: session_data.expires_at.timestamp(),
                nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()),
                global_signature,
            })
        }

        pub fn get_session(&self, session_id: &str) -> Option<PendingOriginSession> {
            let guard = self.sessions.read();
            guard.get(session_id).map(|data| data.session.clone())
        }

        pub fn remove_session(&self, session_id: &str) {
            self.sessions.write().remove(session_id);
        }
    }

    impl PendingOriginSession {
        pub fn is_expired(&self) -> bool {
            Utc::now() > self.expires_at
        }
    }

    pub fn verify_origin_signature(
        origin_pubkey_b64: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        server_x25519_pubkey: &str,
        expires_at: i64,
        origin_signature: &str,
    ) -> bool {
        let verifier = match Ed25519Verifier::from_base64(origin_pubkey_b64) {
            Some(v) => v,
            None => return false,
        };

        let message = format!(
            "{}|{}|{}|{}|{}",
            session_id, key_id, mesh_id, server_x25519_pubkey, expires_at
        );

        verifier.verify(&message, origin_signature)
    }

    pub fn verify_global_signature(
        global_pubkey_b64: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        server_x25519_pubkey: &str,
        expires_at: i64,
        global_signature: &str,
    ) -> bool {
        let verifier = match Ed25519Verifier::from_base64(global_pubkey_b64) {
            Some(v) => v,
            None => return false,
        };

        let message = format!(
            "{}|{}|{}|{}|{}",
            session_id, key_id, mesh_id, server_x25519_pubkey, expires_at
        );

        verifier.verify(&message, global_signature)
    }

    fn derive_origin_session_key(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
        let mut combined = Vec::with_capacity(salt.len() + info.len() + shared_secret.len());
        combined.extend_from_slice(salt);
        combined.extend_from_slice(info);
        combined.extend_from_slice(shared_secret);

        let hash = Sha256::digest(&combined);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    pub fn derive_session_key_from_origin_signed(
        client_secret_key: &[u8; 32],
        server_public_key: &str,
    ) -> Option<[u8; 32]> {
        let server_pk_bytes = URL_SAFE_NO_PAD.decode(server_public_key).ok()?;
        if server_pk_bytes.len() != 32 {
            return None;
        }

        let mut server_pk_array = [0u8; 32];
        server_pk_array.copy_from_slice(&server_pk_bytes);

        let client_static = StaticSecret::from(*client_secret_key);
        let server_pk = X25519PublicKey::from(server_pk_array);
        let shared_secret = client_static.diffie_hellman(&server_pk);

        Some(derive_origin_session_key(
            shared_secret.as_bytes(),
            b"origin-integrity-session",
            b"waf-origin-integrity",
        ))
    }
}

#[cfg(not(feature = "origin_key_exchange"))]
#[allow(unused_imports)]
pub mod origin_key_exchange {
    use super::{SESSION_ID_HEADER as _, SIG_HEADER_PREFIX as _};

    pub struct OriginKeyExchangeManager;

    impl OriginKeyExchangeManager {
        pub fn new(_: [u8; 32], _: u64, _: usize) -> Self {
            unreachable!(
                "OriginKeyExchangeManager::new() called without origin_key_exchange feature enabled"
            )
        }
    }

    pub type OriginSignedSessionKey = ();
    pub type PendingOriginSession = ();

    pub fn verify_origin_signature(
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
        _: &str,
    ) -> bool {
        unreachable!("verify_origin_signature() called without origin_key_exchange feature enabled")
    }

    pub fn verify_global_signature(
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
        _: &str,
    ) -> bool {
        unreachable!("verify_global_signature() called without origin_key_exchange feature enabled")
    }
}
