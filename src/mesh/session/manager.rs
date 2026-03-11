//! Generic session manager with key rotation
//!
//! Provides a session manager that handles key exchange, session storage,
//! and automatic key rotation for forward secrecy.

use crate::mesh::kem::kem_trait::KemSession;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
    #[error("Session expired")]
    SessionExpired,
    #[error("Key rotation failed: {0}")]
    RotationFailed(String),
}

#[derive(Clone)]
pub struct SessionConfig {
    pub max_session_age: Duration,
    pub rotation_interval: Duration,
    pub max_sessions: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_session_age: Duration::from_secs(3600),   // 1 hour
            rotation_interval: Duration::from_secs(2700), // 45 minutes
            max_sessions: 10000,
        }
    }
}

impl SessionConfig {
    pub fn new(max_session_age_secs: u64, rotation_interval_secs: u64) -> Self {
        Self {
            max_session_age: Duration::from_secs(max_session_age_secs),
            rotation_interval: Duration::from_secs(rotation_interval_secs),
            max_sessions: 10000,
        }
    }
}

#[derive(Clone)]
pub struct Session<K: KemSession + Clone> {
    pub id: String,
    pub peer_id: String,
    pub peer_public_key: K::PublicKey,
    pub local_public_key: K::PublicKey,
    pub local_secret_key: K::SecretKey,
    pub ciphertext: Vec<u8>, // Encapsulated key sent to peer
    pub session_key: Vec<u8>,
    pub key_version: u64,
    pub established_at: Instant,
    pub last_rotated: Instant,
}

impl<K: KemSession + Clone> Session<K> {
    pub fn new(
        id: String,
        peer_id: String,
        peer_public_key: K::PublicKey,
        local_public_key: K::PublicKey,
        local_secret_key: K::SecretKey,
        ciphertext: Vec<u8>,
        session_key: Vec<u8>,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            peer_id,
            peer_public_key,
            local_public_key,
            local_secret_key,
            ciphertext,
            session_key,
            key_version: 0,
            established_at: now,
            last_rotated: now,
        }
    }

    pub fn is_expired(&self, config: &SessionConfig) -> bool {
        self.established_at.elapsed() >= config.max_session_age
    }

    pub fn should_rotate(&self, config: &SessionConfig) -> bool {
        self.last_rotated.elapsed() >= config.rotation_interval
    }
}

pub struct SessionManager<K: KemSession + Clone> {
    sessions: Arc<DashMap<String, Session<K>>>,
    config: SessionConfig,
}

impl<K: KemSession + Clone> SessionManager<K> {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            config,
        }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn establish(
        &self,
        peer_id: &str,
        peer_public_key: K::PublicKey,
    ) -> Result<Session<K>, SessionError> {
        let (local_pk, local_sk) =
            K::generate_keypair().map_err(|e| SessionError::KeyExchangeFailed(e.to_string()))?;

        let (ciphertext, shared_secret) = K::encapsulate(&peer_public_key)
            .map_err(|e| SessionError::KeyExchangeFailed(e.to_string()))?;

        let session_id = generate_session_id();
        let session_key = derive_session_key(shared_secret.as_ref(), &session_id, peer_id, 0);

        let session = Session::new(
            session_id,
            peer_id.to_string(),
            peer_public_key,
            local_pk,
            local_sk,
            ciphertext,
            session_key,
        );

        self.sessions.insert(session.id.clone(), session.clone());

        Ok(session)
    }

    pub fn establish_with_ciphertext(
        &self,
        peer_id: &str,
        peer_public_key: K::PublicKey,
        local_public_key: K::PublicKey,
        local_secret_key: K::SecretKey,
        ciphertext: &[u8],
    ) -> Result<Session<K>, SessionError> {
        let shared_secret = K::decapsulate(ciphertext, &local_secret_key)
            .map_err(|e| SessionError::KeyExchangeFailed(e.to_string()))?;

        let session_id = generate_session_id();
        let session_key = derive_session_key(shared_secret.as_ref(), &session_id, peer_id, 0);

        let session = Session::new(
            session_id,
            peer_id.to_string(),
            peer_public_key,
            local_public_key,
            local_secret_key,
            ciphertext.to_vec(),
            session_key,
        );

        self.sessions.insert(session.id.clone(), session.clone());

        Ok(session)
    }

    pub fn get(&self, session_id: &str) -> Option<Session<K>> {
        self.sessions.get(session_id).map(|s| s.value().clone())
    }

    pub fn get_by_peer(&self, peer_id: &str) -> Option<Session<K>> {
        self.sessions
            .iter()
            .find(|s| s.peer_id == peer_id)
            .map(|s| s.value().clone())
    }

    pub fn remove(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn rotate_session(&self, session_id: &str) -> Result<Session<K>, SessionError> {
        let mut session = self
            .sessions
            .get(session_id)
            .map(|s| s.value().clone())
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        let new_version = session.key_version + 1;
        let new_key = derive_session_key(
            &session.session_key,
            &session.id,
            &session.peer_id,
            new_version,
        );

        session.session_key = new_key;
        session.key_version = new_version;
        session.last_rotated = Instant::now();

        self.sessions.insert(session.id.clone(), session.clone());

        Ok(session)
    }

    pub fn rotate_stale_sessions(&self) -> Vec<Session<K>> {
        let mut rotated = Vec::new();

        for mut session in self.sessions.iter_mut() {
            if session.should_rotate(&self.config) {
                let new_version = session.key_version + 1;
                let new_key = derive_session_key(
                    &session.session_key,
                    &session.id,
                    &session.peer_id,
                    new_version,
                );

                session.session_key = new_key;
                session.key_version = new_version;
                session.last_rotated = Instant::now();

                rotated.push(session.clone());
            }
        }

        rotated
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut removed = 0;

        self.sessions.retain(|_id, session| {
            let should_remove = session.is_expired(&self.config);
            if should_remove {
                removed += 1;
            }
            !should_remove
        });

        removed
    }

    pub fn get_local_public_key(&self, session_id: &str) -> Option<K::PublicKey> {
        self.sessions
            .get(session_id)
            .map(|s| s.local_public_key.clone())
    }

    pub fn get_ciphertext(&self, session_id: &str) -> Option<Vec<u8>> {
        self.sessions.get(session_id).map(|s| s.ciphertext.clone())
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

fn generate_session_id() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = rand::random::<[u8; 24]>();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn derive_session_key(
    shared_secret: &[u8],
    session_id: &str,
    peer_id: &str,
    version: u64,
) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret);
    hasher.update(session_id.as_bytes());
    hasher.update(peer_id.as_bytes());
    hasher.update(version.to_le_bytes());

    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::kem::MlKem768;

    fn test_config() -> SessionConfig {
        SessionConfig {
            max_session_age: Duration::from_secs(3600),
            rotation_interval: Duration::from_secs(2700),
            max_sessions: 100,
        }
    }

    #[test]
    fn test_establish_session() {
        let manager: SessionManager<MlKem768> = SessionManager::new(test_config());

        let (pk, _sk) = MlKem768::generate_keypair().unwrap();

        let session = manager.establish("peer-1", pk.clone()).unwrap();

        assert_eq!(session.peer_id, "peer-1");
        assert_eq!(session.key_version, 0);
        assert_eq!(session.session_key.len(), 32);
    }

    #[test]
    fn test_rotate_session() {
        let manager: SessionManager<MlKem768> = SessionManager::new(test_config());

        let (pk, _sk) = MlKem768::generate_keypair().unwrap();

        let session = manager.establish("peer-1", pk).unwrap();
        let original_key = session.session_key.clone();

        let rotated = manager.rotate_session(&session.id).unwrap();

        assert_eq!(rotated.key_version, 1);
        assert_ne!(rotated.session_key, original_key);
    }

    #[test]
    fn test_get_session() {
        let manager: SessionManager<MlKem768> = SessionManager::new(test_config());

        let (pk, _sk) = MlKem768::generate_keypair().unwrap();

        let session = manager.establish("peer-1", pk).unwrap();

        let retrieved = manager.get(&session.id).unwrap();
        assert_eq!(retrieved.id, session.id);
    }
}
