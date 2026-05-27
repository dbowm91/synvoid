//! ML-KEM-768 Key Exchange Service
//!
//! This module implements the ML-KEM-768 based key exchange protocol for
//! post-quantum secure mesh transport communications.

use std::sync::Arc;
use std::time::Instant;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use parking_lot::RwLock;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::mesh::config::MeshConfig;
use crate::mesh::kem::{KemSession, MlKem768, MlKem768PublicKey};
use crate::mesh::protocol::proto::{
    ml_kem_key_exchange_service_server::MlKemKeyExchangeService as GrpcMlKemKeyExchangeService,
    MlKemKeyConfirm, MlKemKeyConfirmResponse, MlKemKeyOffer, MlKemKeyRequest,
};
use crate::mesh::session::SessionManager;

#[derive(Debug, Clone)]
pub struct MlKemKeyHealth {
    pub key_initialized: bool,
    pub key_age_secs: Option<u64>,
    pub stale_session_count: usize,
    pub expired_session_count: usize,
}

fn generate_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub struct MlKemKeyExchangeService {
    config: Arc<MeshConfig>,
    session_manager: Arc<SessionManager<MlKem768>>,
    node_public_key: Arc<RwLock<Option<MlKem768PublicKey>>>,
    key_generated_at: Arc<RwLock<Option<Instant>>>,
    key_max_age_secs: u64,
}

impl MlKemKeyExchangeService {
    pub fn new(config: Arc<MeshConfig>, session_manager: Arc<SessionManager<MlKem768>>) -> Self {
        Self {
            config,
            session_manager,
            node_public_key: Arc::new(RwLock::new(None)),
            key_generated_at: Arc::new(RwLock::new(None)),
            key_max_age_secs: 3600,
        }
    }

    pub fn generate_node_keypair(&self) -> Result<MlKem768PublicKey, String> {
        let (pk, _sk) = MlKem768::generate_keypair()
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;

        *self.node_public_key.write() = Some(pk.clone());
        *self.key_generated_at.write() = Some(Instant::now());
        Ok(pk)
    }

    pub fn get_public_key(&self) -> Option<MlKem768PublicKey> {
        self.node_public_key.read().clone()
    }

    pub fn get_public_key_base64(&self) -> Option<String> {
        self.node_public_key
            .read()
            .as_ref()
            .map(|pk| URL_SAFE_NO_PAD.encode(pk.as_ref()))
    }

    pub fn get_key_health(&self) -> MlKemKeyHealth {
        let key_initialized = self.node_public_key.read().is_some();
        let key_age_secs = self.key_generated_at.read().map(|t| t.elapsed().as_secs());
        let config = self.session_manager.config();

        let mut stale_session_count = 0;
        let mut expired_session_count = 0;

        for session in self.session_manager.get_all_sessions() {
            if session.is_expired(config) {
                expired_session_count += 1;
            } else if session.should_rotate(config) {
                stale_session_count += 1;
            }
        }

        MlKemKeyHealth {
            key_initialized,
            key_age_secs,
            stale_session_count,
            expired_session_count,
        }
    }
}

#[tonic::async_trait]
impl GrpcMlKemKeyExchangeService for MlKemKeyExchangeService {
    async fn request_key(
        &self,
        request: Request<MlKemKeyRequest>,
    ) -> Result<Response<MlKemKeyOffer>, Status> {
        let req = request.into_inner();

        let mesh_id = req.mesh_id;
        let client_mlkem_pubkey_b64 = req.client_mlkem_pubkey;
        let nonce = req.nonce;

        if mesh_id.is_empty() {
            return Err(Status::invalid_argument("mesh_id is required"));
        }
        if client_mlkem_pubkey_b64.is_empty() {
            return Err(Status::invalid_argument("client_mlkem_pubkey is required"));
        }

        tracing::debug!(
            "ML-KEM key exchange request: mesh_id={}, client_pk={}",
            mesh_id,
            &client_mlkem_pubkey_b64[..client_mlkem_pubkey_b64.len().min(16)]
        );

        let client_mlkem_pubkey_bytes = URL_SAFE_NO_PAD
            .decode(&client_mlkem_pubkey_b64)
            .map_err(|_| Status::invalid_argument("Invalid base64 client_mlkem_pubkey"))?;

        if client_mlkem_pubkey_bytes.len() != MlKem768::PUBLIC_KEY_SIZE {
            return Err(Status::invalid_argument(format!(
                "Invalid public key size: expected {}, got {}",
                MlKem768::PUBLIC_KEY_SIZE,
                client_mlkem_pubkey_bytes.len()
            )));
        }

        let client_pk = MlKem768PublicKey(client_mlkem_pubkey_bytes);

        let server_pk = self
            .node_public_key
            .read()
            .clone()
            .ok_or_else(|| Status::unavailable("Server ML-KEM key not initialized"))?;

        let (ciphertext, _shared_secret) = MlKem768::encapsulate(&client_pk)
            .map_err(|e| Status::internal(format!("Encapsulation failed: {}", e)))?;

        let session_id = generate_session_id();
        let key_id = generate_session_id();

        let expires_at = chrono::Utc::now().timestamp() + 3600;

        let origin_mesh_id = self.config.mesh_name.clone().unwrap_or_default();
        let origin_ed25519_pubkey = self
            .config
            .origin_signing_key
            .as_ref()
            .and_then(|k| k.public_key_base64.clone())
            .unwrap_or_default();

        let sign_message = format!(
            "{}|{}|{}|{}|{}",
            session_id,
            key_id,
            mesh_id,
            URL_SAFE_NO_PAD.encode(server_pk.as_ref()),
            URL_SAFE_NO_PAD.encode(&ciphertext)
        );

        let origin_signature = if let Some(ref signer_config) = self.config.origin_signing_key {
            let private_key = signer_config.private_key.as_ref().ok_or_else(|| {
                tracing::error!("ML-KEM exchange requires signing key but none configured");
                Status::internal("Signing key not configured")
            })?;
            let signing_key = SigningKey::from_bytes(private_key);
            let signature = signing_key.sign(sign_message.as_bytes());
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        } else {
            String::new()
        };

        if let Err(e) = self
            .session_manager
            .establish(&format!("peer_{}", key_id), client_pk)
        {
            tracing::warn!("Failed to establish session: {}", e);
        }

        let offer = MlKemKeyOffer {
            session_id,
            key_id,
            mesh_id,
            server_mlkem_pubkey: URL_SAFE_NO_PAD.encode(server_pk.as_ref()),
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
            origin_mesh_id,
            origin_ed25519_pubkey,
            origin_signature,
            expires_at,
            nonce,
        };

        Ok(Response::new(offer))
    }

    async fn confirm_key(
        &self,
        request: Request<MlKemKeyConfirm>,
    ) -> Result<Response<MlKemKeyConfirmResponse>, Status> {
        let req = request.into_inner();

        let session_id = req.session_id;
        let client_mlkem_pubkey_b64 = req.client_mlkem_pubkey;

        if session_id.is_empty() {
            return Err(Status::invalid_argument("session_id is required"));
        }

        tracing::debug!("ML-KEM key confirm: session_id={}", session_id);

        let session = match self.session_manager.get(&session_id) {
            Some(s) => s,
            None => {
                return Ok(Response::new(MlKemKeyConfirmResponse {
                    success: false,
                    error: "Session not found".to_string(),
                }))
            }
        };

        let client_mlkem_pubkey_bytes = URL_SAFE_NO_PAD
            .decode(&client_mlkem_pubkey_b64)
            .map_err(|_| Status::invalid_argument("Invalid base64 client_mlkem_pubkey"))?;

        if client_mlkem_pubkey_bytes.len() != MlKem768::PUBLIC_KEY_SIZE {
            return Err(Status::invalid_argument(format!(
                "Invalid public key size: expected {}, got {}",
                MlKem768::PUBLIC_KEY_SIZE,
                client_mlkem_pubkey_bytes.len()
            )));
        }

        let client_pk = MlKem768PublicKey(client_mlkem_pubkey_bytes);
        if client_pk.as_ref() != session.peer_public_key.as_ref() {
            return Ok(Response::new(MlKemKeyConfirmResponse {
                success: false,
                error: "Public key mismatch".to_string(),
            }));
        }

        let decapsulated_secret =
            MlKem768::decapsulate(&session.ciphertext, &session.local_secret_key).map_err(|e| {
                tracing::warn!("ML-KEM decapsulation failed during confirm: {}", e);
                Status::internal("Decapsulation failed")
            })?;

        use subtle::ConstantTimeEq;
        if decapsulated_secret
            .as_ref()
            .ct_eq(session.session_key.as_ref())
            .into()
        {
            tracing::debug!(
                "ML-KEM key confirm verified: session_id={}, shared_secret_present=true",
                session_id
            );
            Ok(Response::new(MlKemKeyConfirmResponse {
                success: true,
                error: String::new(),
            }))
        } else {
            tracing::warn!(
                "ML-KEM key confirm failed: shared secret mismatch for session_id={}",
                session_id
            );
            Ok(Response::new(MlKemKeyConfirmResponse {
                success: false,
                error: "Shared secret mismatch".to_string(),
            }))
        }
    }
}
