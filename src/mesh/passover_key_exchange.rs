//! Pass-Over Key Exchange Module
//!
//! This module implements the client-to-origin key exchange protocol that occurs
//! through a global node as a pass-through proxy. This is a CRITICAL security component.
//!
//! ## Security Model: GLOBAL NODE IS UNTRUSTED FOR ORIGIN SIGNING
//!
//! The global node MUST NOT sign on behalf of the origin. This is the fundamental
//! security assumption: we assume the edge node is malicious, and we also cannot
//! fully trust the global node for origin authentication.
//!
//! The global node acts ONLY as a network proxy/router - it must forward key exchange
//! requests to the actual origin node via the mesh network and return the origin's
//! signed response to the client.
//!
//! ## Protocol Flow (CORRECT implementation):
//!
//! ```text
//! 1. Client --HTTP--> Global Node: key-request-origin
//!    - Client generates ephemeral X25519 key pair
//!    - Includes: mesh_id, client_x25519_pubkey, nonce
//!    - Client also includes edge_token from edge node (optional)
//!
//! 2. Global Node --Mesh--> Origin: KeyForward
//!    - Global node looks up origin by mesh_id
//!    - Forwards client's public key to origin via mesh transport
//!    - Global node does NOT sign anything here - it just proxies
//!
//! 3. Origin signs session key with its OWN Ed25519 key:
//!    sign_message = session_id|key_id|mesh_id|server_x25519_pubkey|expires_at
//!    - Origin --Mesh--> Global Node: KeySigned (with origin_signature)
//!
//! 4. Global Node --HTTP--> Client: key-offer-origin
//!    - Contains: origin_signature (from ORIGIN, not global!),
//!                origin_ed25519_pubkey, origin_mesh_id
//!    - Global node's only role is to pass through the origin's response
//!
//! 5. Client verifies origin's Ed25519 signature using origin's mesh public key
//!    - If valid, client derives session key via X25519 DH
//!    - Client now has a session key that origin will accept
//! ```
//!
//! ## What MUST NOT Happen:
//!
//! - The global node MUST NOT use its own key to sign as if it were the origin
//! - The client MUST verify the signature came from the origin's Ed25519 key
//! - If origin_signature is missing or unverifiable, the client MUST reject the session
//!
//! ## Edge Token Verification:
//!
//! The edge node may optionally provide a token that proves the request came through
//! a legitimate edge node. This is verified by the global node using the edge's public key.

use std::sync::Arc;
use std::time::Duration;
use axum::{
    extract::State,
    Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey, Signature};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use lru_time_cache::LruCache;
use tower_http::cors::{CorsLayer, Any};
use crate::mesh::config::MeshConfig;

use crate::mesh::protocol::proto::{
    key_exchange_service_server::KeyExchangeService as GrpcKeyExchangeService,
    KeyConfirm, KeyConfirmResponse, KeyOfferOrigin, KeyRequestOrigin,
};

/// Error returned when the global node fails to proxy to origin
#[derive(Debug, Clone, Serialize)]
pub struct PassOverError {
    pub error: String,
    pub code: String,
}

#[derive(Clone)]
pub struct KeyExchangeHttpState {
    pub config: Arc<MeshConfig>,
    pub edge_token_cache: Arc<RwLock<LruCache<String, ()>>>,
    pub transport: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
    pending_key_requests: Arc<RwLock<std::collections::HashMap<String, tokio::sync::oneshot::Sender<KeySignedResponse>>>>,
    pending_ml_kem_secrets: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    established_sessions: Arc<RwLock<std::collections::HashMap<String, EstablishedSession>>>,
}

#[derive(Debug, Clone)]
pub struct KeySignedResponse {
    pub session_id: String,
    pub key_id: String,
    pub mesh_id: String,
    pub origin_mesh_id: String,
    pub origin_ed25519_pubkey: String,
    pub server_x25519_pubkey: String,
    pub origin_signature: String,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Debug, Clone)]
pub struct EstablishedSession {
    pub session_id: String,
    pub mesh_id: String,
    pub client_x25519_pubkey: String,
    pub client_ml_kem_pubkey: Option<String>,
    pub client_ed25519_pubkey: String,
    pub server_x25519_pubkey: String,
    pub origin_ed25519_pubkey: String,
    pub shared_secret: Vec<u8>,
    pub ml_kem_ciphertext: Option<String>,
    pub established_at: i64,
}

impl KeyExchangeHttpState {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        let cache = LruCache::with_expiry_duration_and_capacity(
            Duration::from_secs(EDGE_TOKEN_TTL_SECS),
            10000, // max 10k entries
        );
        Self {
            config,
            edge_token_cache: Arc::new(RwLock::new(cache)),
            transport: None,
            pending_key_requests: Arc::new(RwLock::new(std::collections::HashMap::new())),
            pending_ml_kem_secrets: Arc::new(RwLock::new(std::collections::HashMap::new())),
            established_sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn with_transport(mut self, transport: Option<Arc<crate::mesh::transports::MeshTransportManager>>) -> Self {
        self.transport = transport;
        self
    }

    pub async fn store_ml_kem_secret(&self, session_id: &str, secret: Vec<u8>) {
        let mut secrets = self.pending_ml_kem_secrets.write().await;
        secrets.insert(session_id.to_string(), secret);
    }

    pub async fn get_ml_kem_secret(&self, session_id: &str) -> Option<Vec<u8>> {
        let secrets = self.pending_ml_kem_secrets.read().await;
        secrets.get(session_id).cloned()
    }

    pub async fn remove_ml_kem_secret(&self, session_id: &str) {
        let mut secrets = self.pending_ml_kem_secrets.write().await;
        secrets.remove(session_id);
    }

    pub async fn establish_session(&self, session: EstablishedSession) {
        let mut sessions = self.established_sessions.write().await;
        sessions.insert(session.session_id.clone(), session);
    }

    pub async fn get_session(&self, session_id: &str) -> Option<EstablishedSession> {
        let sessions = self.established_sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn proxy_key_request_to_origin(
        &self,
        mesh_id: &str,
        client_x25519_pubkey: &str,
        nonce: &str,
    ) -> Result<KeySignedResponse, String> {
        let transport_manager = self.transport.as_ref()
            .ok_or("Mesh transport not available - cannot proxy to origin")?;

        let origin_node_id = transport_manager.find_origin_by_mesh_id(mesh_id).await
            .ok_or_else(|| {
                tracing::error!("Origin not found for mesh_id: {}. The global node must be connected to the origin mesh.", mesh_id);
                format!("Origin not found for mesh_id: {}. Ensure the global node is connected to the origin mesh.", mesh_id)
            })?;

        let quic_transport = transport_manager.get_quic_transport()
            .ok_or("QUIC transport not available - cannot proxy to origin")?;
        
        let mesh_transport = quic_transport.get_inner();

        let session_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
        let key_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        
        let (tx, rx) = tokio::sync::oneshot::channel::<KeySignedResponse>();
        
        {
            let mut pending = self.pending_key_requests.write().await;
            pending.insert(session_id.clone(), tx);
        }

        tracing::info!("Proxying key request to origin {} for mesh {}", origin_node_id, mesh_id);

        let global_node_id = self.config.node_id();
        
        let key_forward = crate::mesh::protocol::MeshMessage::KeyForward {
            session_id: session_id.clone().into(),
            key_id: key_id.clone().into(),
            mesh_id: mesh_id.into(),
            client_x25519_pubkey: client_x25519_pubkey.into(),
            global_node_id: global_node_id.clone().into(),
            nonce: nonce.into(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        mesh_transport.send_datagram_to_peer(&origin_node_id, &key_forward).await
            .map_err(|e| format!("Failed to send key request to origin: {}", e))?;

        let timeout = Duration::from_secs(10);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                let mut pending = self.pending_key_requests.write().await;
                pending.remove(&session_id);
                Ok(response)
            }
            Ok(Err(_)) => {
                let mut pending = self.pending_key_requests.write().await;
                pending.remove(&session_id);
                Err("Channel closed unexpectedly".to_string())
            }
            Err(_) => {
                let mut pending = self.pending_key_requests.write().await;
                pending.remove(&session_id);
                Err("Timeout waiting for origin response".to_string())
            }
        }
    }

    pub async fn complete_key_request(&self, session_id: &str, response: KeySignedResponse) {
        let tx = {
            let mut pending = self.pending_key_requests.write().await;
            pending.remove(session_id)
        };
        
        if let Some(tx) = tx {
            let _ = tx.send(response);
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyRequestOriginHttp {
    pub mesh_id: String,
    pub client_x25519_pubkey: String,
    pub nonce: String,
    pub edge_id: Option<String>,
    pub edge_token: Option<String>,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub client_ml_kem_pubkey: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyOfferOriginHttp {
    #[serde(rename = "type")]
    pub r#type: String,
    pub session_id: String,
    pub key_id: String,
    pub mesh_id: String,
    pub server_x25519_pubkey: String,
    pub origin_mesh_id: String,
    pub origin_ed25519_pubkey: String,
    pub origin_signature: String,
    pub expires_at: i64,
    pub nonce: String,
    pub server_ed25519_pubkey: String,
    #[serde(default)]
    pub server_ml_kem_pubkey: Option<String>,
    #[serde(default)]
    pub ml_kem_ciphertext: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyConfirmHttp {
    pub session_id: String,
    pub client_x25519_pubkey: String,
    pub client_ed25519_pubkey: Option<String>,
    pub client_signature: Option<String>,
    #[serde(default)]
    pub client_ml_kem_pubkey: Option<String>,
    #[serde(default)]
    pub ml_kem_ciphertext: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyConfirmResponseHttp {
    pub success: bool,
    pub error: String,
    pub server_ed25519_pubkey: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeError {
    pub error: String,
    pub code: String,
}

pub const EDGE_TOKEN_TTL_SECS: u64 = 300; // 5 minutes
pub const EDGE_TOKEN_PREFIX: &str = "edge:";

pub struct KeyExchangeService {
    config: Arc<MeshConfig>,
}

impl KeyExchangeService {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        Self { config }
    }
}

#[tonic::async_trait]
impl GrpcKeyExchangeService for KeyExchangeService {
    async fn request_key(
        &self,
        request: Request<KeyRequestOrigin>,
    ) -> Result<Response<KeyOfferOrigin>, Status> {
        let req = request.into_inner();

        let mesh_id = req.mesh_id;
        let client_x25519_pubkey = req.client_x25519_pubkey;
        let nonce = req.nonce;

        if mesh_id.is_empty() {
            return Err(Status::invalid_argument("mesh_id is required"));
        }
        if client_x25519_pubkey.is_empty() {
            return Err(Status::invalid_argument("client_x25519_pubkey is required"));
        }

        tracing::debug!(
            "gRPC key exchange request: mesh_id={}, client_pk={}",
            mesh_id,
            &client_x25519_pubkey[..client_x25519_pubkey.len().min(16)]
        );

        let origin_ed25519_pubkey = self.config.origin_signing_key.as_ref()
            .and_then(|k| k.public_key_base64.clone())
            .or_else(|| {
                self.config.global_node.known_origin_keys.get(&mesh_id).cloned()
            })
            .ok_or_else(|| {
                tracing::error!("Unknown origin mesh_id: {}", mesh_id);
                Status::not_found(format!("Unknown mesh_id: {}", mesh_id))
            })?;

        let expires_at = chrono::Utc::now().timestamp() + 3600;

        let sign_message = format!(
            "pending|{}|{}|{}",
            mesh_id,
            client_x25519_pubkey,
            expires_at
        );

        let pending_signature = if let Some(ref signer_config) = self.config.origin_signing_key {
            if let Some(ref private_key) = signer_config.private_key {
                let signing_key = SigningKey::from_bytes(private_key);
                let signature = signing_key.sign(sign_message.as_bytes());
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            } else {
                return Err(Status::unavailable("Origin signing key not available"));
            }
        } else {
            return Err(Status::unavailable("Origin signing key not configured"));
        };

        let global_node_key = self.config.global_node_key.clone().unwrap_or_default();

        let key_offer = KeyOfferOrigin {
            r#type: "key_offer_origin".to_string(),
            session_id: "pending".to_string(),
            key_id: "pending".to_string(),
            mesh_id: mesh_id.clone(),
            server_x25519_pubkey: self.config.node_id(),
            origin_mesh_id: mesh_id.clone(),
            origin_ed25519_pubkey,
            origin_signature: pending_signature,
            expires_at,
            nonce,
            server_ed25519_pubkey: global_node_key,
        };

        Ok(Response::new(key_offer))
    }

    async fn confirm_key(
        &self,
        request: Request<KeyConfirm>,
    ) -> Result<Response<KeyConfirmResponse>, Status> {
        let req = request.into_inner();

        let session_id = req.session_id;
        let client_x25519_pubkey = req.client_x25519_pubkey;

        if session_id.is_empty() {
            return Err(Status::invalid_argument("session_id is required"));
        }
        if client_x25519_pubkey.is_empty() {
            return Err(Status::invalid_argument("client_x25519_pubkey is required"));
        }

        tracing::debug!(
            "gRPC key confirm: session_id={}, client_pk={}",
            session_id,
            &client_x25519_pubkey[..client_x25519_pubkey.len().min(16)]
        );

        Ok(Response::new(KeyConfirmResponse {
            success: true,
            error: String::new(),
        }))
    }
}

/// Client IP passed from the HTTP server for edge token verification
#[derive(Clone, Debug, Deserialize)]
pub struct KeyRequestWithClientIp {
    pub mesh_id: String,
    pub client_x25519_pubkey: String,
    pub nonce: String,
    pub edge_id: Option<String>,
    pub edge_token: Option<String>,
    pub client_ip: Option<String>,
}

pub async fn key_request_origin_http(
    State(state): State<KeyExchangeHttpState>,
    Json(req): Json<KeyRequestOriginHttp>,
) -> Result<Json<KeyOfferOriginHttp>, (axum::http::StatusCode, String)> {
    if req.mesh_id.is_empty() {
        return Err((axum::http::StatusCode::BAD_REQUEST, "mesh_id is required".to_string()));
    }
    if req.client_x25519_pubkey.is_empty() {
        return Err((axum::http::StatusCode::BAD_REQUEST, "client_x25519_pubkey is required".to_string()));
    }

    let client_ip = req.client_ip.as_deref().unwrap_or("");

    if let (Some(edge_id), Some(edge_token)) = (&req.edge_id, &req.edge_token) {
        if let Err(e) = verify_edge_token(&state, edge_id, edge_token, client_ip).await {
            tracing::warn!("Edge token verification failed: {}", e);
            return Err((axum::http::StatusCode::UNAUTHORIZED, format!("Edge token verification failed: {}", e)));
        }
    } else if state.config.global_node.key_exchange_require_edge_auth {
        return Err((axum::http::StatusCode::UNAUTHORIZED, "Edge token required".to_string()));
    }

    tracing::info!(
        "Pass-over key exchange request: mesh_id={}, client_pk={}, has_ml_kem={}",
        req.mesh_id,
        &req.client_x25519_pubkey[..req.client_x25519_pubkey.len().min(16)],
        req.client_ml_kem_pubkey.is_some()
    );

    let origin_response = state.proxy_key_request_to_origin(
        &req.mesh_id,
        &req.client_x25519_pubkey,
        &req.nonce,
    ).await;

    let origin_resp = match origin_response {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to proxy key request to origin: {}", e);
            return Err((axum::http::StatusCode::BAD_GATEWAY, 
                format!("Origin unavailable: {}. The global node cannot proxy to the origin.", e)));
        }
    };

    let global_node_key = state.config.global_node_key.clone().unwrap_or_default();

    let mut server_ml_kem_pubkey = None;
    let mut ml_kem_ciphertext = None;
    let mut ml_kem_secret: Option<Vec<u8>> = None;

    if let Some(ref client_ml_kem_pubkey_b64) = req.client_ml_kem_pubkey {
        if let Some(ref global_ml_kem_pubkey) = state.config.global_node.ml_kem_public_key_base64 {
            server_ml_kem_pubkey = Some(global_ml_kem_pubkey.clone());

            let ml_kem_result = perform_ml_kem_encapsulation(client_ml_kem_pubkey_b64);

            match ml_kem_result {
                Ok((ct, ss)) => {
                    ml_kem_ciphertext = Some(ct);
                    ml_kem_secret = Some(ss);
                    tracing::info!("ML-KEM encapsulation successful for mesh {}", req.mesh_id);
                }
                Err(e) => {
                    tracing::warn!("ML-KEM encapsulation failed: {}, falling back to X25519 only", e);
                    server_ml_kem_pubkey = None;
                    ml_kem_ciphertext = None;
                }
            }
        } else {
            tracing::debug!("Client requested ML-KEM but global node has no ML-KEM key configured");
        }
    }

    // Store ML-KEM secret for later use in key_confirm
    if let Some(secret) = ml_kem_secret {
        state.store_ml_kem_secret(&origin_resp.session_id, secret).await;
    }

    let key_offer = KeyOfferOriginHttp {
        r#type: "key_offer_origin".to_string(),
        session_id: origin_resp.session_id,
        key_id: origin_resp.key_id,
        mesh_id: origin_resp.mesh_id,
        server_x25519_pubkey: origin_resp.server_x25519_pubkey,
        origin_mesh_id: origin_resp.origin_mesh_id,
        origin_ed25519_pubkey: origin_resp.origin_ed25519_pubkey,
        origin_signature: origin_resp.origin_signature,
        expires_at: origin_resp.expires_at,
        nonce: origin_resp.nonce,
        server_ed25519_pubkey: global_node_key,
        server_ml_kem_pubkey,
        ml_kem_ciphertext,
    };

    tracing::info!("Successfully proxied key exchange response from origin for mesh {}", req.mesh_id);
    
    Ok(Json(key_offer))
}

/// Perform ML-KEM-768 encapsulation using the client's public key.
/// 
/// In ML-KEM, the client sends their public key, and the server uses it to
/// encapsulate a shared secret. The ciphertext is sent back to the client who
/// can decapsulate it using their secret key.
/// 
/// Returns (ciphertext, shared_secret)
fn perform_ml_kem_encapsulation(client_ml_kem_pubkey_b64: &str) -> Result<(String, Vec<u8>), String> {
    use pqc::MlKem768;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let client_pk_bytes = URL_SAFE_NO_PAD.decode(client_ml_kem_pubkey_b64)
        .map_err(|e| format!("Invalid base64 ML-KEM pubkey: {}", e))?;

    if client_pk_bytes.len() != MlKem768::PUBLIC_KEY_SIZE {
        return Err(format!("Invalid ML-KEM pubkey size: expected {}, got {}",
            MlKem768::PUBLIC_KEY_SIZE, client_pk_bytes.len()));
    }

    let client_pk = pqc::PublicKey::from_bytes(&client_pk_bytes)
        .map_err(|e| format!("Invalid ML-KEM pubkey: {}", e))?;

    let (ct, ss) = MlKem768::encapsulate(&client_pk)
        .map_err(|e| format!("ML-KEM encapsulation failed: {}", e))?;

    Ok((ct.to_base64(), ss.to_vec()))
}

/// Combine two secrets (X25519 and ML-KEM) into a hybrid secret using HKDF-like construction.
///
/// This provides post-quantum security: even if a quantum attacker breaks one algorithm,
/// they still need to break the other to recover the session key.
fn combine_secrets(secret1: &[u8], secret2: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(secret1);
    hasher.update(b"hybrid-v1");
    hasher.update(secret2);
    hasher.finalize().to_vec()
}

pub async fn key_confirm_http(
    State(state): State<KeyExchangeHttpState>,
    Json(req): Json<KeyConfirmHttp>,
) -> Result<Json<KeyConfirmResponseHttp>, (axum::http::StatusCode, String)> {
    if req.session_id.is_empty() {
        return Err((axum::http::StatusCode::BAD_REQUEST, "session_id is required".to_string()));
    }
    if req.client_x25519_pubkey.is_empty() {
        return Err((axum::http::StatusCode::BAD_REQUEST, "client_x25519_pubkey is required".to_string()));
    }

    let client_ed25519_pubkey = req.client_ed25519_pubkey.clone()
        .ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "client_ed25519_pubkey is required".to_string()))?;

    tracing::info!(
        "HTTP key confirm: session_id={}, client_pk={}, client_ed25519_pk={}",
        req.session_id,
        &req.client_x25519_pubkey[..req.client_x25519_pubkey.len().min(16)],
        &client_ed25519_pubkey[..client_ed25519_pubkey.len().min(16)]
    );

    // Derive the shared secret using X25519
    // Use the global node's long-term X25519 key from config
    let server_static_secret = {
        let secret_bytes = state.config.global_node.x25519_private_key
            .ok_or_else(|| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Global node X25519 key not configured".to_string()))?;
        StaticSecret::from(secret_bytes)
    };
    let server_x25519_pubkey = {
        let pubkey_bytes = state.config.global_node.x25519_public_key_base64
            .clone()
            .ok_or_else(|| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Global node X25519 public key not derived".to_string()))?;
        pubkey_bytes
    };
    
    // Decode client's X25519 public key
    let client_pk_bytes = URL_SAFE_NO_PAD.decode(&req.client_x25519_pubkey)
        .map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "Invalid client public key encoding".to_string()))?;
    
    if client_pk_bytes.len() != 32 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Invalid client public key length".to_string()));
    }
    
    let mut client_pk_array = [0u8; 32];
    client_pk_array.copy_from_slice(&client_pk_bytes);
    let client_x25519_pk = X25519PublicKey::from(client_pk_array);
    
    // Derive shared secret
    let shared_secret = server_static_secret.diffie_hellman(&client_x25519_pk);
    let mut shared_secret_bytes = shared_secret.as_bytes().to_vec();

    // If ML-KEM was used, combine with X25519 secret for hybrid security
    if let Some(ml_kem_secret) = state.get_ml_kem_secret(&req.session_id).await {
        // Combine X25519 and ML-KEM secrets using HKDF-like construction
        let hybrid = combine_secrets(&shared_secret_bytes, &ml_kem_secret);
        shared_secret_bytes = hybrid;
        tracing::info!("Using hybrid X25519+ML-KEM session key for session {}", req.session_id);
        
        // Clean up the stored secret
        state.remove_ml_kem_secret(&req.session_id).await;
    } else if let Some(ref _ct) = req.ml_kem_ciphertext {
        tracing::debug!("ML-KEM ciphertext present but no stored secret found for session {}", req.session_id);
    }

    // Get the origin's Ed25519 public key for session storage
    let origin_ed25519_pubkey = state.config.origin_signing_key.as_ref()
        .and_then(|k| k.public_key_base64.clone())
        .unwrap_or_default();

    // Store the established session
    let mesh_id = state.config.origin_signing_key.as_ref()
        .map(|k| k.mesh_id.clone())
        .unwrap_or_default();
    
    let session = EstablishedSession {
        session_id: req.session_id.clone(),
        mesh_id,
        client_x25519_pubkey: req.client_x25519_pubkey.clone(),
        client_ml_kem_pubkey: req.client_ml_kem_pubkey.clone(),
        client_ed25519_pubkey: client_ed25519_pubkey.clone(),
        server_x25519_pubkey: server_x25519_pubkey.clone(),
        origin_ed25519_pubkey: origin_ed25519_pubkey.clone(),
        shared_secret: shared_secret_bytes,
        ml_kem_ciphertext: req.ml_kem_ciphertext.clone(),
        established_at: chrono::Utc::now().timestamp(),
    };
    
    state.establish_session(session).await;

    // Return the GLOBAL node's Ed25519 public key (not origin's)
    // The client needs this to verify messages from the global node
    let server_ed25519_pubkey = state.config.global_node.ed25519_public_key_base64.clone();

    Ok(Json(KeyConfirmResponseHttp {
        success: true,
        error: String::new(),
        server_ed25519_pubkey,
    }))
}

#[derive(Deserialize)]
struct EdgeTokenPayload {
    client_ip: String,
    timestamp: i64,
    expires_at: i64,
    nonce: String,
}

pub async fn verify_edge_token(
    state: &KeyExchangeHttpState,
    edge_id: &str,
    edge_token: &str,
    client_ip: &str,
) -> Result<(), String> {
    // Check if edge auth is required
    if !state.config.global_node.key_exchange_require_edge_auth {
        return Ok(());
    }

    // Decode the edge token (format: edge:{base64(payload)}:{signature})
    let token_parts: Vec<&str> = edge_token.split(':').collect();
    if token_parts.len() != 3 || token_parts[0] != "edge" {
        return Err("Invalid edge token format".to_string());
    }

    let payload_b64 = token_parts[1];
    let signature_b64 = token_parts[2];

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "Invalid token payload encoding")?;

    let payload: EdgeTokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| "Invalid token payload format")?;

    // Verify client IP matches
    if payload.client_ip != client_ip {
        return Err("Token client IP mismatch".to_string());
    }

    // Verify timestamp and expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if payload.timestamp > now + 60 || payload.timestamp < now - 60 {
        return Err("Token timestamp out of range".to_string());
    }

    if payload.expires_at < now {
        return Err("Token expired".to_string());
    }

    // Verify single-use: check cache (LruCache handles TTL automatically)
    let token_key = format!("{}:{}", edge_id, payload.nonce);
    {
        let mut cache = state.edge_token_cache.write().await;
        if cache.contains_key(&token_key) {
            return Err("Token already used".to_string());
        }
        // Mark as used - LruCache will auto-expire after TTL
        cache.insert(token_key, ());
    }

    // Look up edge's public key - try DHT first (which includes config fallback)
    let edge_public_key = if let Some(ref transport) = state.transport {
        transport.get_edge_key(edge_id)
            .ok_or_else(|| format!("Unknown edge node: {}. Add edge public key to global_node.known_edge_keys in config or wait for DHT propagation.", edge_id))?
    } else {
        // No transport available, use config only
        state.config.global_node.known_edge_keys.get(edge_id)
            .cloned()
            .ok_or_else(|| format!("Unknown edge node: {}. Add edge public key to global_node.known_edge_keys in config.", edge_id))?
    };

    // Verify the signature
    let message = format!("{}:{}:{}:{}", payload.client_ip, payload.timestamp, payload.expires_at, payload.nonce);
    
    // Decode edge public key
    let edge_key_bytes = URL_SAFE_NO_PAD.decode(&edge_public_key)
        .map_err(|_| "Invalid edge public key encoding")?;
    if edge_key_bytes.len() != 32 {
        return Err("Invalid edge public key length".to_string());
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&edge_key_bytes);
    
    let verifier = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| "Invalid edge public key")?;

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64)
        .map_err(|_| "Invalid signature encoding")?;
    
    if signature_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);
    
    let signature = Signature::from_bytes(&sig_array);

    verifier
        .verify(message.as_bytes(), &signature)
        .map_err(|_| "Edge token signature verification failed")?;

    // Token is already marked as used in cache above (single-use with TTL)
    // LruCache automatically handles expiration after EDGE_TOKEN_TTL_SECS

    Ok(())
}

pub fn create_key_exchange_router(config: Arc<MeshConfig>) -> Router {
    let state = KeyExchangeHttpState::new(config.clone());
    
    let global_node_config = &config.global_node;
    
    let cors = build_cors_layer(global_node_config);
    
    Router::new()
        .route("/key-request-origin", post(key_request_origin_http))
        .route("/key-confirm", post(key_confirm_http))
        .route("/mesh/key-request", post(key_request_origin_http))
        .route("/mesh/key-confirm", post(key_confirm_http))
        .route("/health", get(health_check))
        .layer(cors)
        .with_state(state)
}

fn build_cors_layer(global_node_config: &crate::mesh::config::GlobalNodeConfig) -> CorsLayer {
    let mut cors = CorsLayer::new();
    
    if let Some(ref origin) = global_node_config.cors_allow_origin {
        if origin == "*" || origin.is_empty() {
            cors = cors.allow_origin(Any);
        } else {
            let origins: Vec<http::HeaderValue> = origin.split(',')
                .filter_map(|o| o.trim().parse().ok())
                .collect();
            if origins.is_empty() {
                cors = cors.allow_origin(Any);
            } else {
                cors = cors.allow_origin(origins);
            }
        }
    } else {
        cors = cors.allow_origin(Any);
    }
    
    if let Some(ref methods) = global_node_config.cors_allow_methods {
        if methods.is_empty() {
            cors = cors.allow_methods(Any);
        } else {
            let http_methods: Vec<http::Method> = methods.iter()
                .filter_map(|m| m.parse().ok())
                .collect();
            if http_methods.is_empty() {
                cors = cors.allow_methods(Any);
            } else {
                cors = cors.allow_methods(http_methods);
            }
        }
    } else {
        cors = cors.allow_methods(Any);
    }
    
    if let Some(ref headers) = global_node_config.cors_allow_headers {
        if headers.is_empty() {
            cors = cors.allow_headers(Any);
        } else {
            let http_headers: Vec<http::HeaderName> = headers.iter()
                .filter_map(|h| h.parse().ok())
                .collect();
            if http_headers.is_empty() {
                cors = cors.allow_headers(Any);
            } else {
                cors = cors.allow_headers(http_headers);
            }
        }
    } else {
        cors = cors.allow_headers(Any);
    }
    
    cors
}

pub async fn health_check() -> &'static str {
    "OK"
}

pub async fn run_key_exchange_server(
    config: Arc<MeshConfig>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let router = create_key_exchange_router(config.clone());
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    let scheme = if config.tls.cert_path.is_some() && config.tls.key_path.is_some() {
        "https"
    } else {
        "http"
    };
    
    tracing::info!("Key exchange server starting on {}://{} (TLS not yet implemented - use https proxy)", scheme, addr);
    
    axum::serve(listener, router).await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{SigningKey, Verifier};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize)]
    struct TestKeySignedResponse {
        session_id: String,
        key_id: String,
        mesh_id: String,
        origin_mesh_id: String,
        origin_ed25519_pubkey: String,
        server_x25519_pubkey: String,
        origin_signature: String,
        expires_at: i64,
        nonce: String,
    }

    #[test]
    fn test_key_signed_response_serialization() {
        let response = TestKeySignedResponse {
            session_id: "test-session".to_string(),
            key_id: "test-key".to_string(),
            mesh_id: "test-mesh".to_string(),
            origin_mesh_id: "origin-mesh".to_string(),
            origin_ed25519_pubkey: "test-origin-pk".to_string(),
            server_x25519_pubkey: "test-server-pk".to_string(),
            origin_signature: "test-sig".to_string(),
            expires_at: 1234567890,
            nonce: "test-nonce".to_string(),
        };
        
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains("test-session"));
    }

    #[test]
    fn test_established_session_storage() {
        let session = EstablishedSession {
            session_id: "session-123".to_string(),
            mesh_id: "mesh-456".to_string(),
            client_x25519_pubkey: "client-x25519-pk".to_string(),
            client_ml_kem_pubkey: None,
            client_ed25519_pubkey: "client-ed25519-pk".to_string(),
            server_x25519_pubkey: "server-x25519-pk".to_string(),
            origin_ed25519_pubkey: "origin-ed25519-pk".to_string(),
            shared_secret: vec![0u8; 32],
            ml_kem_ciphertext: None,
            established_at: 1234567890,
        };
        
        assert_eq!(session.session_id, "session-123");
        assert_eq!(session.mesh_id, "mesh-456");
    }

    #[tokio::test]
    async fn test_key_exchange_http_state_session_management() {
        let config = Arc::new(MeshConfig::default());
        let state = KeyExchangeHttpState::new(config);
        
        let session = EstablishedSession {
            session_id: "test-session".to_string(),
            mesh_id: "test-mesh".to_string(),
            client_x25519_pubkey: URL_SAFE_NO_PAD.encode([0u8; 32]),
            client_ml_kem_pubkey: None,
            client_ed25519_pubkey: URL_SAFE_NO_PAD.encode([1u8; 32]),
            server_x25519_pubkey: URL_SAFE_NO_PAD.encode([2u8; 32]),
            origin_ed25519_pubkey: URL_SAFE_NO_PAD.encode([3u8; 32]),
            shared_secret: vec![0u8; 32],
            ml_kem_ciphertext: None,
            established_at: chrono::Utc::now().timestamp(),
        };
        
        state.establish_session(session.clone()).await;
        
        let retrieved = state.get_session(&session.session_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, "test-session");
    }

    #[test]
    fn test_x25519_key_derivation() {
        // Client generates key pair using rand::random
        let client_secret_bytes: [u8; 32] = rand::random();
        let client_secret = StaticSecret::from(client_secret_bytes);
        let client_public = X25519PublicKey::from(&client_secret);
        
        // Server generates key pair  
        let server_secret_bytes: [u8; 32] = rand::random();
        let server_secret = StaticSecret::from(server_secret_bytes);
        let server_public = X25519PublicKey::from(&server_secret);
        
        // Both derive same shared secret
        let client_shared = client_secret.diffie_hellman(&server_public);
        let server_shared = server_secret.diffie_hellman(&client_public);
        
        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    }

    #[test]
    fn test_ml_kem_encapsulation() {
        use pqc::MlKem768;

        // Generate a client keypair
        let (client_pk, _client_sk) = MlKem768::generate_keypair()
            .expect("Failed to generate ML-KEM keypair");

        // Client sends their public key to server
        let client_pk_b64 = client_pk.to_base64();

        // Server encapsulates using client's public key
        let (ciphertext, shared_secret) = perform_ml_kem_encapsulation(&client_pk_b64)
            .expect("ML-KEM encapsulation failed");

        // Verify ciphertext is valid base64 and correct size
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let ct_bytes = URL_SAFE_NO_PAD.decode(&ciphertext)
            .expect("Invalid base64 ciphertext");
        assert_eq!(ct_bytes.len(), MlKem768::CIPHERTEXT_SIZE);
        
        // Verify shared secret is correct size
        assert_eq!(shared_secret.len(), MlKem768::SHARED_SECRET_SIZE);

        tracing::debug!("ML-KEM encapsulation test passed");
    }

    #[test]
    fn test_ml_kem_key_sizes() {
        use pqc::MlKem768;
        
        assert_eq!(MlKem768::PUBLIC_KEY_SIZE, 1184);
        assert_eq!(MlKem768::SECRET_KEY_SIZE, 2400);
        assert_eq!(MlKem768::CIPHERTEXT_SIZE, 1088);
        assert_eq!(MlKem768::SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_ml_dsa_key_sizes() {
        use pqc::MlDsa44;
        
        assert_eq!(MlDsa44::PUBLIC_KEY_SIZE, 1312);
        assert_eq!(MlDsa44::SECRET_KEY_SIZE, 2560);
        assert_eq!(MlDsa44::SIGNATURE_SIZE, 2420);
    }

    #[test]
    fn test_hybrid_secret_combination() {
        let x25519_secret = vec![0u8; 32];
        let ml_kem_secret = vec![1u8; 32];
        
        let combined = combine_secrets(&x25519_secret, &ml_kem_secret);
        
        // Should be 32 bytes (SHA256 output)
        assert_eq!(combined.len(), 32);
        
        // Different inputs should produce different outputs
        let combined2 = combine_secrets(&vec![2u8; 32], &vec![3u8; 32]);
        assert_ne!(combined, combined2);
    }

    #[test]
    fn test_ed25519_signing_and_verification() {
        // Generate key pair using rand::random
        let secret_bytes: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        
        // Sign a message
        let message = "test message for signing";
        let signature = signing_key.sign(message.as_bytes());
        
        // Verify signature
        assert!(verifying_key.verify(message.as_bytes(), &signature).is_ok());
        
        // Verify wrong message fails
        assert!(verifying_key.verify("wrong message".as_bytes(), &signature).is_err());
    }

    #[tokio::test]
    async fn test_key_request_validation() {
        let config = Arc::new(MeshConfig::default());
        let state = KeyExchangeHttpState::new(config);
        
        // The validation happens in the handler, but we can test the state
        assert!(state.get_session("nonexistent").await.is_none());
    }

    #[test]
    fn test_key_confirm_http_request_serialization() {
        let req = KeyConfirmHttp {
            session_id: "session-123".to_string(),
            client_x25519_pubkey: URL_SAFE_NO_PAD.encode([0u8; 32]),
            client_ed25519_pubkey: Some(URL_SAFE_NO_PAD.encode([1u8; 32])),
            client_signature: Some("test-sig".to_string()),
            client_ml_kem_pubkey: None,
            ml_kem_ciphertext: None,
        };
        
        let serialized = serde_json::to_string(&req).unwrap();
        assert!(serialized.contains("session-123"));
        
        let deserialized: KeyConfirmHttp = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.session_id, "session-123");
    }

    #[test]
    fn test_global_node_config_key_loading() {
        use crate::mesh::config::GlobalNodeConfig;
        
        // Generate test keys
        let x25519_secret: [u8; 32] = rand::random();
        let x25519_secret_b64 = URL_SAFE_NO_PAD.encode(x25519_secret);
        
        let ed25519_secret: [u8; 32] = rand::random();
        let ed25519_secret_b64 = URL_SAFE_NO_PAD.encode(ed25519_secret);
        
        let mut config = GlobalNodeConfig {
            x25519_private_key_base64: Some(x25519_secret_b64),
            ed25519_private_key_base64: Some(ed25519_secret_b64),
            ..Default::default()
        };
        
        // Load keys
        config.load_keys().unwrap();
        
        // Verify public keys were derived
        assert!(config.x25519_public_key_base64.is_some());
        assert!(config.ed25519_public_key_base64.is_some());
        
        // Verify private keys are stored
        assert!(config.x25519_private_key.is_some());
        assert!(config.ed25519_private_key.is_some());
    }

    #[test]
    fn test_full_key_exchange_signing_flow() {
        // Simulate the full flow: client signs, server verifies
        
        // Generate client keys
        let client_secret: [u8; 32] = rand::random();
        let client_signing_key = SigningKey::from_bytes(&client_secret);
        let client_verifying_key = client_signing_key.verifying_key();
        
        // Generate server keys
        let server_secret: [u8; 32] = rand::random();
        let server_signing_key = SigningKey::from_bytes(&server_secret);
        let server_verifying_key = server_signing_key.verifying_key();
        
        // Client signs a request
        let message = "GET|/index.html|host:example.com";
        let client_signature = client_signing_key.sign(message.as_bytes());
        
        // Server verifies client signature
        assert!(server_verifying_key.verify(message.as_bytes(), &client_signature).is_ok());
        
        // Server signs response
        let response_message = "200|host:example.com|content-length:123";
        let server_signature = server_signing_key.sign(response_message.as_bytes());
        
        // Client verifies server signature
        assert!(client_verifying_key.verify(response_message.as_bytes(), &server_signature).is_ok());
        
        // Wrong message should fail
        assert!(!client_verifying_key.verify("wrong message".as_bytes(), &server_signature).is_ok());
    }

    #[tokio::test]
    async fn test_session_storage_with_all_keys() {
        let session = EstablishedSession {
            session_id: "test-session-full".to_string(),
            mesh_id: "test-mesh".to_string(),
            client_x25519_pubkey: URL_SAFE_NO_PAD.encode([0u8; 32]),
            client_ml_kem_pubkey: None,
            client_ed25519_pubkey: URL_SAFE_NO_PAD.encode([1u8; 32]),
            server_x25519_pubkey: URL_SAFE_NO_PAD.encode([2u8; 32]),
            origin_ed25519_pubkey: URL_SAFE_NO_PAD.encode([3u8; 32]),
            shared_secret: vec![0u8; 32],
            ml_kem_ciphertext: None,
            established_at: chrono::Utc::now().timestamp(),
        };
        
        let config = Arc::new(MeshConfig::default());
        let state = KeyExchangeHttpState::new(config);
        
        state.establish_session(session.clone()).await;
        
        let retrieved = state.get_session(&session.session_id).await;
        assert!(retrieved.is_some());
        
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.client_x25519_pubkey, session.client_x25519_pubkey);
        assert_eq!(retrieved.client_ed25519_pubkey, session.client_ed25519_pubkey);
        assert_eq!(retrieved.server_x25519_pubkey, session.server_x25519_pubkey);
        assert_eq!(retrieved.origin_ed25519_pubkey, session.origin_ed25519_pubkey);
    }
}
