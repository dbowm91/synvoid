//! Mesh Transport Layer
//!
#![allow(clippy::type_complexity)]

//! This module implements the QUIC-based mesh transport for inter-node communication.
//!
//! # Architecture
//!
//! The transport layer is split into two main components:
//!
//! - **`MeshTransport`** (this file): The implementation layer that manages QUIC connections,
//!   peer sessions, message routing, and protocol handling. This struct owns the actual
//!   connection state, peer maps, and message dispatch logic.
//!
//! - **`MeshTransportManager`** (in `transport_manager.rs`): The selection and caching layer
//!   that wraps `MeshTransport` with peer selection strategies, connection pooling, and
//!   health-check-based routing. `MeshTransportManager` delegates actual I/O to
//!   `MeshTransport`.
//!
//! # Extension Files
//!
//! The implementation is split across several sibling files by concern:
//!
//! - `transport_peer.rs` — Per-peer session management, handshake, message handlers
//! - `transport_dns.rs` — DNS record synchronization over mesh
//! - `transport_proxy.rs` — Proxy request forwarding between mesh peers
//! - `transport_manager.rs` — Transport manager with peer selection/caching
//!
//! All extension files use `use super::*` to access `MeshTransport` fields, which
//! must be `pub(crate)` visibility.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru_time_cache::LruCache;

use bytes::Bytes;
use dashmap::DashMap;
use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
use http_body::Body as HttpBody;
use http_body_util::combinators::BoxBody;
use hyper::{Request, Response};
use parking_lot::RwLock;

use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

use crate::mesh::cert::MeshCertManager;
use crate::mesh::config::{MeshConfig, MeshPeerConfig};
use crate::mesh::dht::DEFAULT_GET_BY_PREFIX_LIMIT;
use crate::mesh::kem::MlKem768;
use crate::mesh::organization::{MemberCertificate, OrgPublicKey};
use crate::mesh::protocol::{
    DhtRecord, MeshMessage, MeshPeerInfo, ProviderInfo, RouteQueryResult, UpstreamInfo,
    MESH_MESSAGE_VERSION,
};
use crate::mesh::session::SessionManager;
use crate::mesh::topology::{MeshTopology, PeerStatus};
use crate::mesh::transport_types::MeshStreamPool;
use crate::tunnel::quic::runtime::QuicRuntime;

pub use crate::mesh::transports::MeshTransportManager;

pub use crate::mesh::transport_core::{
    get_time_validation_error_count, validate_system_time, MeshTransportError,
    MAX_REASONABLE_TIMESTAMP, MIN_REASONABLE_TIMESTAMP,
};

pub use crate::mesh::transport_types::{MeshGlobalRateLimiter, MeshPeerConnection};

// SAFETY_REASON: Reserved for future protocol handling
#[allow(dead_code)]
pub(crate) const MAX_PENDING_CONNECTIONS: usize = 100;
pub(crate) const CONNECTION_RATE_LIMIT_WINDOW_SECS: u64 = 60;
// SAFETY_REASON: Reserved for future protocol handling
#[allow(dead_code)]
pub(crate) const MAX_MESSAGE_QUEUE_SIZE: usize = 1000;
// SAFETY_REASON: Reserved for future protocol handling
#[allow(dead_code)]
pub(crate) const DEFAULT_MAX_PEER_MESSAGE_RATE: usize = 1000;
pub(crate) const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
pub(crate) const MAX_BATCH_KEYS: usize = 10000;
pub(crate) const MAX_HTTP_BODY_SIZE: usize = 50 * 1024 * 1024;
pub(crate) const PEER_RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub(crate) const SNAPSHOT_REQUEST_RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub(crate) const MAX_SNAPSHOT_REQUESTS_PER_WINDOW: usize = 10;
pub(crate) const MAX_SNAPSHOT_RECORDS: usize = 10000;
/// Maximum duration for a block received from another node (24 hours)
pub(crate) const MAX_BLOCK_DURATION_SECS: u64 = 86400;

pub struct MeshTransport {
    pub(crate) config: Arc<MeshConfig>,
    pub(crate) topology: Arc<MeshTopology>,
    pub(crate) cert_manager: Arc<RwLock<MeshCertManager>>,
    pub(crate) runtime: Option<Arc<QuicRuntime>>,
    pub(crate) running: Arc<RwLock<bool>>,
    pub(crate) shutdown_tx: Arc<RwLock<Option<broadcast::Sender<()>>>>,
    pub(crate) peer_connections: Arc<DashMap<String, MeshPeerConnection>>,
    pub(crate) auth_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    pub(crate) connection_times: Arc<RwLock<Vec<Instant>>>,
    pub(crate) query_dedup: Arc<Mutex<HashMap<String, oneshot::Sender<RouteQueryResult>>>>,
    pub(crate) pending_queries: Arc<Mutex<PendingQueryManager>>,
    pub(crate) pending_dht_queries: Arc<Mutex<HashMap<String, oneshot::Sender<DhtRecord>>>>,
    pub(crate) pending_serverless_invocations: Arc<
        Mutex<HashMap<String, oneshot::Sender<crate::mesh::protocol::ServerlessInvokeResponse>>>,
    >,
    pub(crate) pending_consistent_read_responses: Arc<
        Mutex<HashMap<String, tokio::sync::oneshot::Sender<crate::mesh::protocol::MeshMessage>>>,
    >,
    pub(crate) pending_snapshot_responses:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    pub(crate) pending_snapshot_transfers: Arc<Mutex<HashMap<String, InProgressSnapshot>>>,
    pub(crate) auth_failures: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub(crate) peer_message_times: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub(crate) snapshot_request_times: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub(crate) global_rate_limiter: Arc<MeshGlobalRateLimiter>,
    pub(crate) org_manager: Arc<RwLock<crate::mesh::organization::OrganizationManager>>,
    pub(crate) org_key_manager: Arc<crate::mesh::org_key_manager::OrgKeyManager>,
    pub(crate) tier_key_store: Option<Arc<RwLock<crate::mesh::dht::TierKeyStore>>>,
    pub(crate) tier_key_encryption:
        Option<Arc<crate::mesh::tier_key_encryption::TierKeyEncryption>>,
    pub(crate) origin_ed25519_signer: Option<Arc<crate::integrity::Ed25519Signer>>,
    pub(crate) mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    pub(crate) record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
    pub(crate) routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
    pub(crate) threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
    pub(crate) yara_rules: Option<Arc<crate::mesh::yara_rules::YaraRulesManager>>,
    pub(crate) seen_messages: Arc<RwLock<lru_time_cache::LruCache<String, Instant>>>,
    pub(crate) stake_manager: Option<Arc<crate::mesh::dht::StakeManager>>,
    pub(crate) mlkem_session_manager: Option<Arc<SessionManager<MlKem768>>>,
    pub(crate) backend_pool: Option<Arc<crate::mesh::backend::MeshBackendPool>>,
    #[cfg(feature = "dns")]
    pub(crate) dns_resolver: Option<Arc<dyn crate::dns::resolver::DnsResolver>>,
    #[cfg(feature = "dns")]
    pub(crate) dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>>,
    #[cfg(feature = "dns")]
    pub(crate) dns_zones: Arc<RwLock<Option<Arc<crate::dns::server::ShardedZoneStore>>>>,
    #[allow(clippy::type_complexity)]
    pub(crate) site_config_sync_tx: Arc<
        RwLock<
            Option<
                mpsc::Sender<(
                    String,
                    String,
                    Option<crate::mesh::protocol::ProxyCachePreferences>,
                )>,
            >,
        >,
    >,
    pub(crate) verification_manager:
        Arc<RwLock<Option<Arc<crate::mesh::verification::VerificationTaskManager>>>>,
    pub(crate) revocation_list: Option<Arc<crate::mesh::peer_auth::GlobalNodeRevocationList>>,
    pub(crate) serverless_manager:
        Arc<RwLock<Option<Arc<crate::serverless::manager::ServerlessManager>>>>,
    #[cfg(feature = "dns")]
    pub(crate) ownership_challenge_store: Arc<RwLock<OwnershipChallengeStore>>,
    pub(crate) raft_instance: Arc<RwLock<Option<Arc<crate::mesh::raft::instance::RaftInstance>>>>,
    pub(crate) pending_membership_changes: Arc<tokio::sync::Mutex<Vec<PendingMembershipChange>>>,
    pub(crate) edge_replica_manager:
        Arc<RwLock<Option<Arc<crate::mesh::raft::edge_replica::EdgeReplicaManager>>>>,
    pub(crate) raft_proposal_replay_cache:
        Arc<tokio::sync::Mutex<crate::mesh::raft::state_machine::ReplayProtectionCache>>,
}

#[derive(Clone, Debug)]
pub struct PendingMembershipChange {
    pub node_id: u64,
    pub action: MembershipChangeAction,
    pub authorized_at: u64,
}

#[derive(Debug)]
pub struct InProgressSnapshot {
    pub request_id: String,
    pub total_size: u64,
    pub data: Vec<u8>,
    pub vote: Vec<u8>,
    pub meta: Vec<u8>,
    pub offset: u64,
    pub created_at: Instant,
    pub sender_node_id: Option<String>,
}

impl InProgressSnapshot {
    pub fn new(request_id: String, total_size: u64, vote: Vec<u8>, meta: Vec<u8>) -> Self {
        Self {
            request_id,
            total_size,
            data: Vec::new(),
            vote,
            meta,
            offset: 0,
            created_at: Instant::now(),
            sender_node_id: None,
        }
    }

    pub fn with_sender(
        request_id: String,
        total_size: u64,
        vote: Vec<u8>,
        meta: Vec<u8>,
        sender: String,
    ) -> Self {
        Self {
            request_id,
            total_size,
            data: Vec::new(),
            vote,
            meta,
            offset: 0,
            created_at: Instant::now(),
            sender_node_id: Some(sender),
        }
    }

    pub fn sender(&self) -> Option<&str> {
        self.sender_node_id.as_deref()
    }

    pub fn validate_sender(&self, sender: &str) -> bool {
        self.sender_node_id
            .as_ref()
            .map(|s| s == sender)
            .unwrap_or(true)
    }

    pub fn add_chunk(
        &mut self,
        chunk_offset: u64,
        chunk_data: Vec<u8>,
        is_last: bool,
        expected_sender: Option<&str>,
    ) -> bool {
        if let (Some(sender), Some(expected)) = (&self.sender_node_id, expected_sender) {
            if sender != expected {
                tracing::warn!(
                    "Chunk sender mismatch: expected {}, got {}",
                    expected,
                    sender
                );
                return false;
            }
        }
        if chunk_offset != self.offset {
            tracing::warn!(
                "Chunk offset mismatch: expected {}, got {}",
                self.offset,
                chunk_offset
            );
            return false;
        }
        let chunk_len = chunk_data.len() as u64;
        if self.data.len() as u64 + chunk_len > self.total_size {
            tracing::warn!(
                "Chunk would exceed total size: current {} + chunk {} > total {}",
                self.data.len(),
                chunk_len,
                self.total_size
            );
            return false;
        }
        self.data.extend(chunk_data);
        self.offset += chunk_len;
        if is_last && self.offset != self.total_size {
            tracing::warn!(
                "Snapshot complete flag set but offset {} != total_size {}",
                self.offset,
                self.total_size
            );
            return false;
        }
        true
    }

    pub fn is_complete(&self) -> bool {
        self.offset >= self.total_size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipChangeAction {
    Add,
    Remove,
}

#[derive(Clone)]
pub struct Http01Challenge {
    pub key_authorization: String,
    pub upstream_id: String,
    pub created_at: Instant,
}

#[derive(Clone)]
pub struct Dns01Challenge {
    pub domain: String,
    pub txt_record_name: String,
    pub txt_record_value: String,
    pub upstream_id: String,
    pub created_at: Instant,
}

pub struct OwnershipChallengeStore {
    http_challenges: LruCache<String, Http01Challenge>,
    dns_challenges: LruCache<String, Dns01Challenge>,
}

impl OwnershipChallengeStore {
    pub fn new() -> Self {
        Self {
            http_challenges: LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(300),
                1000,
            ),
            dns_challenges: LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(300),
                1000,
            ),
        }
    }

    pub fn store_http_challenge(&mut self, token: String, challenge: Http01Challenge) {
        self.http_challenges.insert(token, challenge);
    }

    pub fn get_http_challenge(&mut self, token: &str) -> Option<String> {
        self.http_challenges
            .get(token)
            .map(|c| c.key_authorization.clone())
    }

    pub fn store_dns_challenge(&mut self, txt_record_name: String, challenge: Dns01Challenge) {
        self.dns_challenges.insert(txt_record_name, challenge);
    }

    #[cfg(feature = "dns")]
    pub fn get_dns_challenge(&mut self, txt_record_name: &str) -> Option<Dns01Challenge> {
        self.dns_challenges.get(txt_record_name).cloned()
    }
}

impl Default for OwnershipChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MeshTransport {
    fn clone(&self) -> Self {
        Self {
            backend_pool: self.backend_pool.clone(),
            config: self.config.clone(),
            topology: self.topology.clone(),
            cert_manager: self.cert_manager.clone(),
            runtime: self.runtime.clone(),
            running: self.running.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            peer_connections: self.peer_connections.clone(),
            auth_keys: self.auth_keys.clone(),
            connection_times: self.connection_times.clone(),
            query_dedup: self.query_dedup.clone(),
            pending_queries: self.pending_queries.clone(),
            pending_dht_queries: self.pending_dht_queries.clone(),
            pending_serverless_invocations: self.pending_serverless_invocations.clone(),
            pending_consistent_read_responses: self.pending_consistent_read_responses.clone(),
            pending_snapshot_responses: self.pending_snapshot_responses.clone(),
            pending_snapshot_transfers: self.pending_snapshot_transfers.clone(),
            auth_failures: self.auth_failures.clone(),
            peer_message_times: self.peer_message_times.clone(),
            snapshot_request_times: self.snapshot_request_times.clone(),
            global_rate_limiter: self.global_rate_limiter.clone(),
            org_manager: self.org_manager.clone(),
            org_key_manager: self.org_key_manager.clone(),
            tier_key_store: self.tier_key_store.clone(),
            tier_key_encryption: self.tier_key_encryption.clone(),
            origin_ed25519_signer: self.origin_ed25519_signer.clone(),
            mesh_signer: self.mesh_signer.clone(),
            record_store: self.record_store.clone(),
            routing_manager: self.routing_manager.clone(),
            threat_intel: self.threat_intel.clone(),
            yara_rules: self.yara_rules.clone(),
            seen_messages: Arc::new(RwLock::new(
                lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                    Duration::from_secs(300),
                    500000,
                ),
            )),
            stake_manager: self.stake_manager.clone(),
            mlkem_session_manager: self.mlkem_session_manager.clone(),
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver.clone(),
            #[cfg(feature = "dns")]
            dns_registry: self.dns_registry.clone(),
            #[cfg(feature = "dns")]
            dns_zones: self.dns_zones.clone(),
            site_config_sync_tx: self.site_config_sync_tx.clone(),
            verification_manager: self.verification_manager.clone(),
            revocation_list: self.revocation_list.clone(),
            serverless_manager: self.serverless_manager.clone(),
            #[cfg(feature = "dns")]
            ownership_challenge_store: self.ownership_challenge_store.clone(),
            raft_instance: self.raft_instance.clone(),
            pending_membership_changes: self.pending_membership_changes.clone(),
            edge_replica_manager: self.edge_replica_manager.clone(),
            raft_proposal_replay_cache: self.raft_proposal_replay_cache.clone(),
        }
    }
}

// SAFETY_REASON: Reserved for message queuing
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct QueuedMessage {
    target_node: String,
    message: Arc<MeshMessage>,
    priority: MessagePriority,
    enqueued_at: Instant,
}

// SAFETY_REASON: Reserved for priority handling
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub(crate) enum MessagePriority {
    High = 2,
    Normal = 1,
    Low = 0,
}

#[derive(Debug)]
pub(crate) struct PendingQueryManager {
    pub(crate) pending: HashMap<String, oneshot::Sender<RouteQueryResult>>,
    pub(crate) collected_providers: HashMap<String, Vec<ProviderInfo>>,
    pub(crate) notify_complete: HashMap<String, tokio::sync::watch::Sender<()>>,
}

impl PendingQueryManager {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            collected_providers: HashMap::new(),
            notify_complete: HashMap::new(),
        }
    }

    pub(crate) fn register(&mut self, query_id: String, sender: oneshot::Sender<RouteQueryResult>) {
        self.pending.insert(query_id.clone(), sender);
        self.collected_providers
            .insert(query_id.clone(), Vec::new());
        let (tx, _) = tokio::sync::watch::channel(());
        self.notify_complete.insert(query_id, tx);
    }

    pub(crate) fn add_provider(&mut self, query_id: &str, provider: ProviderInfo) {
        if let Some(providers) = self.collected_providers.get_mut(query_id) {
            if !providers.iter().any(|p| p.node_id == provider.node_id) {
                providers.push(provider);
            }
        }
        if let Some(tx) = self.notify_complete.get_mut(query_id) {
            let _ = tx.send(());
        }
    }

    pub(crate) fn take(&mut self, query_id: &str) -> Option<oneshot::Sender<RouteQueryResult>> {
        self.collected_providers.remove(query_id);
        self.notify_complete.remove(query_id);
        self.pending.remove(query_id)
    }
}

impl MeshTransport {
    fn get_org_auth_data(&self) -> (Option<MemberCertificate>, Option<OrgPublicKey>) {
        let org_id = self.config.node_identity.genesis_org_id();
        let org_manager = self.org_manager.read();
        let member_cert = org_manager
            .get_organization(&org_id)
            .and_then(|org| org.get_valid_member_certificate(&self.config.node_id()))
            .cloned();

        let org_pub_key = self.org_key_manager.get_org_public_key(&org_id);

        (member_cert, org_pub_key)
    }

    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        cert_manager: Arc<RwLock<MeshCertManager>>,
        record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
        _routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
        threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
        mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        stake_manager: Option<Arc<crate::mesh::dht::StakeManager>>,
        backend_pool: Option<Arc<crate::mesh::backend::MeshBackendPool>>,
        #[cfg(feature = "dns")] dns_resolver: Option<Arc<dyn crate::dns::resolver::DnsResolver>>,
        #[cfg(feature = "dns")] dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>>,
    ) -> Self {
        let is_genesis = config.is_genesis_node();

        let auth_keys: HashMap<String, Vec<u8>> = HashMap::new();

        let global_rate_limiter = Arc::new(MeshGlobalRateLimiter::new(
            config.routing.mesh_messages_per_sec,
            config.routing.route_queries_per_minute,
        ));

        let origin_ed25519_signer = config.origin_signing_key.as_ref().and_then(|key_cfg| {
            key_cfg
                .private_key
                .map(|pk| Arc::new(crate::integrity::Ed25519Signer::new(pk)))
        });

        let seen_messages =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 10000);

        let tier_key_store = if config
            .role
            .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        {
            Some(Arc::new(RwLock::new(crate::mesh::dht::TierKeyStore::new())))
        } else {
            None
        };

        let mlkem_session_manager = if let Some(ref mlkem_config) = config.mlkem {
            if mlkem_config.enabled {
                let session_config: crate::mesh::session::SessionConfig =
                    mlkem_config.clone().into();
                Some(Arc::new(SessionManager::<MlKem768>::new(session_config)))
            } else {
                None
            }
        } else {
            None
        };

        let tier_key_encryption = if config.role.is_global() {
            if let Some(signing_key) = config.signing_key() {
                use hkdf::Hkdf;
                use sha2::Sha256;
                const HKDF_INFO: &[u8] = b"synvoid-tier-key-master";
                let hk = Hkdf::<Sha256>::new(None, signing_key);
                let mut okm = [0u8; 32];
                if hk.expand(HKDF_INFO, &mut okm).is_ok() {
                    tracing::info!("TierKey DHT encryption enabled for global node");
                    Some(Arc::new(
                        crate::mesh::tier_key_encryption::TierKeyEncryption::new(okm.to_vec()),
                    ))
                } else {
                    tracing::warn!("Failed to derive tier key encryption master key");
                    None
                }
            } else {
                tracing::warn!(
                    "Global node has no signing key - tier key DHT encryption disabled. \
                     Provide genesis_key_base64 in config to enable global node features."
                );
                None
            }
        } else {
            None
        };

        Self {
            backend_pool,
            config: config.clone(),
            topology,
            cert_manager: cert_manager.clone(),
            runtime: None,
            running: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            peer_connections: Arc::new(DashMap::new()),
            auth_keys: Arc::new(RwLock::new(auth_keys)),
            connection_times: Arc::new(RwLock::new(Vec::new())),
            query_dedup: Arc::new(Mutex::new(HashMap::new())),
            pending_queries: Arc::new(Mutex::new(PendingQueryManager::new())),
            pending_dht_queries: Arc::new(Mutex::new(HashMap::new())),
            pending_serverless_invocations: Arc::new(Mutex::new(HashMap::new())),
            pending_consistent_read_responses: Arc::new(Mutex::new(HashMap::new())),
            pending_snapshot_responses: Arc::new(Mutex::new(HashMap::new())),
            pending_snapshot_transfers: Arc::new(Mutex::new(HashMap::new())),
            auth_failures: Arc::new(RwLock::new(HashMap::new())),
            peer_message_times: Arc::new(RwLock::new(HashMap::new())),
            snapshot_request_times: Arc::new(RwLock::new(HashMap::new())),
            global_rate_limiter,
            org_manager: {
                let mut org_mgr = crate::mesh::organization::OrganizationManager::new();
                if is_genesis {
                    org_mgr.init_genesis_org();
                    tracing::info!(
                        "Initialized genesis node - genesis and admin organizations created"
                    );
                }
                Arc::new(RwLock::new(org_mgr))
            },
            org_key_manager: {
                let mgr = crate::mesh::org_key_manager::OrgKeyManager::new(
                    config
                        .node_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    config.role,
                );
                if let Some(ref store) = record_store {
                    mgr.set_record_store(store.clone());
                }
                mgr.set_cert_manager(Arc::clone(&cert_manager));
                Arc::new(mgr)
            },
            tier_key_store,
            tier_key_encryption,
            origin_ed25519_signer,
            mesh_signer,
            record_store,
            routing_manager: None,
            threat_intel,
            yara_rules: None,
            seen_messages: Arc::new(RwLock::new(seen_messages)),
            stake_manager,
            mlkem_session_manager,
            #[cfg(feature = "dns")]
            dns_resolver,
            #[cfg(feature = "dns")]
            dns_registry,
            #[cfg(feature = "dns")]
            dns_zones: Arc::new(RwLock::new(None)),
            site_config_sync_tx: Arc::new(RwLock::new(None)),
            verification_manager: Arc::new(RwLock::new(None)),
            revocation_list: if is_genesis {
                Some(Arc::new(
                    crate::mesh::peer_auth::GlobalNodeRevocationList::new(),
                ))
            } else {
                None
            },
            serverless_manager: Arc::new(RwLock::new(None)),
            #[cfg(feature = "dns")]
            ownership_challenge_store: Arc::new(RwLock::new(OwnershipChallengeStore::new())),
            raft_instance: Arc::new(RwLock::new(None)),
            pending_membership_changes: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            edge_replica_manager: Arc::new(RwLock::new(None)),
            raft_proposal_replay_cache: Arc::new(tokio::sync::Mutex::new(
                crate::mesh::raft::state_machine::ReplayProtectionCache::default(),
            )),
        }
    }

    pub fn set_edge_replica_manager(
        &self,
        manager: Arc<crate::mesh::raft::edge_replica::EdgeReplicaManager>,
    ) {
        *self.edge_replica_manager.write() = Some(manager);
    }

    pub fn set_site_config_sync_callback(
        &self,
        tx: mpsc::Sender<(
            String,
            String,
            Option<crate::mesh::protocol::ProxyCachePreferences>,
        )>,
    ) {
        let mut lock = self.site_config_sync_tx.write();
        *lock = Some(tx);
    }

    #[cfg(feature = "dns")]
    pub fn set_dns_zones(&self, zones: Arc<crate::dns::server::ShardedZoneStore>) {
        let mut lock = self.dns_zones.write();
        *lock = Some(zones);
    }

    pub fn set_verification_manager(
        &self,
        manager: Arc<crate::mesh::verification::VerificationTaskManager>,
    ) {
        *self.verification_manager.write() = Some(manager);
    }

    #[cfg(feature = "dns")]
    pub fn store_http01_challenge(
        &self,
        token: String,
        key_authorization: String,
        upstream_id: String,
    ) {
        let challenge = Http01Challenge {
            key_authorization,
            upstream_id,
            created_at: Instant::now(),
        };
        let mut store = self.ownership_challenge_store.write();
        store.store_http_challenge(token, challenge);
    }

    #[cfg(feature = "dns")]
    pub fn get_http01_challenge(&self, token: &str) -> Option<String> {
        let mut store = self.ownership_challenge_store.write();
        store.get_http_challenge(token)
    }

    #[cfg(feature = "dns")]
    pub fn store_dns01_challenge(
        &self,
        txt_record_name: String,
        domain: String,
        txt_record_value: String,
        upstream_id: String,
    ) {
        let challenge = Dns01Challenge {
            domain,
            txt_record_name: txt_record_name.clone(),
            txt_record_value,
            upstream_id,
            created_at: Instant::now(),
        };
        let mut store = self.ownership_challenge_store.write();
        store.store_dns_challenge(txt_record_name, challenge);
    }

    #[cfg(feature = "dns")]
    pub fn get_dns01_challenge(&self, txt_record_name: &str) -> Option<Dns01Challenge> {
        let mut store = self.ownership_challenge_store.write();
        store.get_dns_challenge(txt_record_name)
    }

    pub fn get_org_manager(&self) -> Arc<RwLock<crate::mesh::organization::OrganizationManager>> {
        self.org_manager.clone()
    }

    pub fn get_record_store(&self) -> Option<Arc<crate::mesh::dht::RecordStoreManager>> {
        self.record_store.clone()
    }

    pub fn get_routing_manager(&self) -> Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>> {
        self.routing_manager.clone()
    }

    pub fn set_routing_manager(
        &mut self,
        manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>,
    ) {
        self.routing_manager = Some(manager);
    }

    pub fn get_tier_key_store(&self) -> Option<Arc<RwLock<crate::mesh::dht::TierKeyStore>>> {
        self.tier_key_store.clone()
    }

    pub fn set_tier_key_encryption(
        &mut self,
        enc: Arc<crate::mesh::tier_key_encryption::TierKeyEncryption>,
    ) {
        self.tier_key_encryption = Some(enc);
    }

    pub fn get_tier_key_encryption(
        &self,
    ) -> Option<Arc<crate::mesh::tier_key_encryption::TierKeyEncryption>> {
        self.tier_key_encryption.clone()
    }

    pub fn get_topology(&self) -> Arc<MeshTopology> {
        self.topology.clone()
    }

    pub fn get_threat_intel(
        &self,
    ) -> Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>> {
        self.threat_intel.clone()
    }

    pub fn get_stake_manager(&self) -> Option<Arc<crate::mesh::dht::StakeManager>> {
        self.stake_manager.clone()
    }

    pub fn get_mlkem_session_manager(&self) -> Option<Arc<SessionManager<MlKem768>>> {
        self.mlkem_session_manager.clone()
    }

    pub fn set_mlkem_session_manager(&mut self, manager: Arc<SessionManager<MlKem768>>) {
        self.mlkem_session_manager = Some(manager);
    }

    pub fn set_raft_instance(&self, instance: Arc<crate::mesh::raft::instance::RaftInstance>) {
        *self.raft_instance.write() = Some(instance);
    }

    pub fn get_raft_instance(
        &self,
    ) -> Arc<RwLock<Option<Arc<crate::mesh::raft::instance::RaftInstance>>>> {
        self.raft_instance.clone()
    }

    pub async fn trigger_membership_change(
        &self,
        node_id_str: &str,
        action: MembershipChangeAction,
    ) {
        let Ok(node_id) = node_id_str.parse::<u64>() else {
            tracing::warn!(
                "Cannot parse node_id '{}' as u64 for Raft membership change",
                node_id_str
            );
            return;
        };

        let pending = PendingMembershipChange {
            node_id,
            action: action.clone(),
            authorized_at: crate::utils::safe_unix_timestamp(),
        };

        let raft_instance = {
            let raft_guard = self.raft_instance.read();
            raft_guard.as_ref().map(|guard| guard.clone())
        };

        let Some(raft_instance) = raft_instance else {
            let mut pending_changes = self.pending_membership_changes.lock().await;
            pending_changes.retain(|p| p.node_id != node_id || p.action != action);
            pending_changes.push(pending);
            return;
        };

        let is_leader = raft_instance.is_leader().await;
        if !is_leader {
            let mut pending_changes = self.pending_membership_changes.lock().await;
            pending_changes.retain(|p| p.node_id != node_id || p.action != action);
            pending_changes.push(pending);
            return;
        }

        match action {
            MembershipChangeAction::Add => {
                tracing::info!("Leader triggering Raft membership add for node {}", node_id);
                let members = std::collections::BTreeSet::from([node_id]);
                match raft_instance
                    .change_membership(openraft::ChangeMembers::AddVoterIds(members), true)
                    .await
                {
                    Ok(index) => {
                        tracing::info!("Node {} added to Raft cluster at index {}", node_id, index);
                    }
                    Err(e) => {
                        tracing::error!("Failed to add node {} to Raft: {}", node_id, e);
                    }
                }
            }
            MembershipChangeAction::Remove => {
                tracing::info!(
                    "Leader triggering Raft membership removal for node {}",
                    node_id
                );
                let members = std::collections::BTreeSet::from([node_id]);
                match raft_instance
                    .change_membership(openraft::ChangeMembers::RemoveVoters(members), false)
                    .await
                {
                    Ok(index) => {
                        tracing::info!(
                            "Node {} removed from Raft cluster at index {}",
                            node_id,
                            index
                        );
                    }
                    Err(e) => {
                        tracing::error!("Failed to remove node {} from Raft: {}", node_id, e);
                    }
                }
            }
        }
    }

    pub async fn process_pending_membership_changes(&self) {
        let mut pending_changes = self.pending_membership_changes.lock().await;
        if pending_changes.is_empty() {
            return;
        }

        let raft_instance = {
            let raft_guard = self.raft_instance.read();
            raft_guard.as_ref().map(|guard| guard.clone())
        };

        let Some(raft_instance) = raft_instance else {
            return;
        };

        let is_leader = raft_instance.is_leader().await;
        if !is_leader {
            return;
        }

        tracing::info!(
            "Processing {} pending membership changes",
            pending_changes.len()
        );

        let mut remaining = Vec::new();
        for change in pending_changes.drain(..) {
            let members = std::collections::BTreeSet::from([change.node_id]);
            let retain = matches!(change.action, MembershipChangeAction::Add);

            match raft_instance.change_membership(members, retain).await {
                Ok(index) => {
                    tracing::info!(
                        "Processed pending membership change for node {} at index {}",
                        change.node_id,
                        index
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to process membership change for node {}: {}",
                        change.node_id,
                        e
                    );
                    remaining.push(change);
                }
            }
        }
        *pending_changes = remaining;
    }

    pub fn announce_edge_key(&self, edge_id: &str, public_key: &str) {
        if let Some(ref record_store) = self.record_store {
            let key = format!("edge_key:{}", edge_id);
            let value = serde_json::json!({
                "edge_id": edge_id,
                "public_key": public_key,
                "announced_at": chrono::Utc::now().timestamp(),
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key, bytes, 86400); // 24 hour TTL
                tracing::debug!("Announced edge key for {} to DHT", edge_id);
            }
        }
    }

    pub fn announce_capabilities(&self, node_id: &str, capabilities: &[String]) {
        if let Some(ref record_store) = self.record_store {
            let ttl = 3600; // 1 hour TTL for capabilities
            for capability in capabilities {
                let key = crate::mesh::dht::keys::DhtKey::node_capability(node_id, capability);
                let key_str = key.as_str();
                let value = serde_json::json!({
                    "node_id": node_id,
                    "capability": capability,
                    "announced_at": chrono::Utc::now().timestamp(),
                });
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    record_store.store_and_announce(key_str.to_string(), bytes, ttl);
                }
            }
            tracing::debug!(
                "Announced {} capabilities for {} to DHT",
                capabilities.len(),
                node_id
            );
        }
    }

    pub fn discover_serverless_functions(
        &self,
    ) -> Vec<crate::mesh::protocol::ServerlessFunctionAnnounce> {
        let Some(record_store) = self.record_store.clone() else {
            tracing::warn!("No record store available for serverless function discovery");
            return Vec::new();
        };

        let dht_records =
            record_store.get_by_prefix("serverless_function:", DEFAULT_GET_BY_PREFIX_LIMIT);
        let mut functions = Vec::new();

        for record in dht_records {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                let function_name = value
                    .get("function_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let node_id = value
                    .get("node_id")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
                let checksum = value
                    .get("checksum")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let routes = value
                    .get("routes")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let allowed_methods = value
                    .get("allowed_methods")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let memory_mb = value
                    .get("memory_mb")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize);
                let timeout_seconds = value.get("timeout_seconds").and_then(|v| v.as_u64());
                let priority = value.get("priority").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

                functions.push(crate::mesh::protocol::ServerlessFunctionAnnounce {
                    function_name,
                    node_id,
                    version,
                    checksum,
                    routes,
                    allowed_methods,
                    memory_mb,
                    timeout_seconds,
                    priority,
                });
            }
        }

        tracing::debug!(
            "Discovered {} serverless functions from DHT",
            functions.len()
        );
        functions
    }

    pub fn announce_serverless(&self) {
        let Some(record_store) = self.record_store.clone() else {
            tracing::warn!("No record store available for serverless announcement");
            return;
        };

        let serverless_manager = self.serverless_manager.read().clone();
        let Some(manager) = serverless_manager else {
            tracing::debug!("No serverless manager configured, skipping announcement");
            return;
        };

        if !manager.is_enabled() {
            tracing::debug!("Serverless not enabled, skipping announcement");
            return;
        }

        let functions = manager.get_all_functions();
        if functions.is_empty() {
            tracing::debug!("No serverless functions configured, skipping announcement");
            return;
        }

        let node_id = self.config.node_id().to_string();

        for (func_name, function) in functions {
            let key = crate::mesh::dht::keys::DhtKey::serverless_function(&func_name);
            let value = serde_json::json!({
                "function_name": func_name,
                "version": 1,
                "node_id": node_id,
                "routes": function.definition.routes,
                "allowed_methods": function.definition.allowed_methods,
                "memory_mb": function.definition.memory_mb,
                "timeout_seconds": function.definition.timeout_seconds,
                "priority": 100,
                "announced_at": chrono::Utc::now().timestamp(),
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key.as_str().to_string(), bytes, 3600);
                tracing::debug!("Announced serverless function {} to DHT", func_name);
            }
        }
    }

    pub async fn attest_capability(
        &self,
        node_id: &str,
        capability: &str,
    ) -> Option<crate::mesh::dht::CapabilityAttestation> {
        if !self.config.role.is_global() {
            tracing::warn!("Only global nodes can attest capabilities");
            return None;
        }

        let peer_state = if node_id == self.config.node_id() {
            Some(crate::mesh::topology::PeerState {
                node_id: node_id.to_string(),
                address: String::new(),
                role: self.config.role,
                status: crate::mesh::topology::PeerStatus::Healthy,
                capabilities: crate::mesh::protocol::MeshCapabilities {
                    can_route: true,
                    can_proxy: true,
                    can_serve_dns: true,
                    is_global: self.config.role.is_global(),
                    waf_enabled: true,
                    max_hops: 10,
                    supported_services: vec![],
                    preferred_transport: None,
                    supported_protocols: vec![],
                },
                upstreams: std::collections::HashSet::new(),
                latency_ms: Some(0),
                first_seen: crate::utils::current_timestamp(),
                last_seen: crate::utils::current_timestamp(),
                is_global: self.config.role.is_global(),
                is_trusted: true,
                connection_handle: None,
                geo: None,
                audit_successes: 0,
                audit_failures: 0,
                performance_audit_successes: 0,
                performance_audit_failures: 0,
                quic_port: None,
                wireguard_port: None,
                advertised_port: None,
                previous_reputation: None,
            })
        } else {
            self.topology.get_peer(node_id).await
        };

        let peer_state = match peer_state {
            Some(p) => p,
            None => {
                tracing::warn!("Cannot attest capability for unknown node: {}", node_id);
                return None;
            }
        };

        if !self.verify_node_capability(&peer_state, capability) {
            tracing::warn!(
                "Node {} does not have capability '{}' - attestation denied",
                node_id,
                capability
            );
            return None;
        }

        let signer = self.mesh_signer.as_ref()?;
        let timestamp = crate::utils::current_timestamp();
        let global_node_id = self.config.node_id();

        let temp_attestation = crate::mesh::dht::CapabilityAttestation::new(
            node_id.to_string(),
            capability.to_string(),
            global_node_id.clone(),
            String::new(),
            vec![],
            timestamp,
        );

        let signature = signer.sign(temp_attestation.signable_content().as_bytes());

        let signer_public_key = signer.get_public_key();

        let attestation = crate::mesh::dht::CapabilityAttestation::new(
            node_id.to_string(),
            capability.to_string(),
            global_node_id,
            signer_public_key,
            signature,
            timestamp,
        );

        if let Some(ref record_store) = self.record_store {
            let key = crate::mesh::dht::keys::DhtKey::capability_attestation(node_id, capability);
            let key_str = key.as_str();
            if let Ok(bytes) = serde_json::to_vec(&attestation) {
                record_store.store_and_announce(key_str.to_string(), bytes, 86400);
                tracing::debug!("Attested capability '{}' for node {}", capability, node_id);
            }
        }

        Some(attestation)
    }

    fn verify_node_capability(
        &self,
        peer_state: &crate::mesh::topology::PeerState,
        capability: &str,
    ) -> bool {
        match capability {
            "dns_server" | "dns" => {
                if peer_state.capabilities.can_serve_dns {
                    if !peer_state.is_global {
                        tracing::warn!(
                            "Node {} claims {} capability but is not a global node - rejecting",
                            peer_state.node_id,
                            capability
                        );
                        return false;
                    }
                    true
                } else {
                    false
                }
            }
            "waf" | "threat_intel" => peer_state.capabilities.waf_enabled,
            "edge_proxy" => peer_state.capabilities.can_proxy,
            "origin" => !peer_state.upstreams.is_empty(),
            _ => {
                tracing::warn!("Unknown capability: {}", capability);
                false
            }
        }
    }

    pub fn get_capability_attestation(
        &self,
        node_id: &str,
        capability: &str,
    ) -> Option<crate::mesh::dht::CapabilityAttestation> {
        let key = crate::mesh::dht::keys::DhtKey::capability_attestation(node_id, capability);
        let key_str = key.as_str();

        if let Some(ref record_store) = self.record_store {
            if let Some(record) = record_store.get(&key_str) {
                return serde_json::from_slice(&record.value).ok();
            }
        }
        None
    }

    pub async fn verify_capability_attestation(
        &self,
        attestation: &crate::mesh::dht::CapabilityAttestation,
    ) -> bool {
        let global_node_id = &attestation.attested_by_global_node;

        let peer_state = self.topology.get_peer(global_node_id).await;

        let Some(peer_state) = peer_state else {
            tracing::warn!(
                "Cannot verify attestation - global node {} not found in topology",
                global_node_id
            );
            return false;
        };

        if !peer_state.is_global {
            tracing::warn!("Attestation signed by non-global node {}", global_node_id);
            return false;
        }

        if !self.verify_node_capability(&peer_state, &attestation.capability) {
            tracing::warn!(
                "Global node {} does not have capability '{}' it attested",
                global_node_id,
                attestation.capability
            );
            return false;
        }

        attestation.verify_signature()
    }

    pub fn publish_single_site_transform_config(
        &self,
        site_id: &str,
        site_config: &crate::config::site::SiteConfig,
    ) {
        let Some(ref record_store) = self.record_store else {
            tracing::warn!("Cannot publish transform config: no record store");
            return;
        };

        let image_poison_config = &site_config.image_poison;
        let static_config = &site_config.r#static;

        let image_protection_json = serde_json::json!({
            "enabled": image_poison_config.enabled,
            "min_size_bytes": image_poison_config.max_dimension.map(|v| v as u64),
            "whitelist_patterns": image_poison_config.whitelist_patterns,
        });
        let image_protection_key = format!("upstream_image_protection:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&image_protection_json) {
            record_store.store_and_announce(image_protection_key, bytes, 3600);
        }

        let site_image_poison_json = serde_json::json!({
            "enabled": image_poison_config.enabled,
            "level": image_poison_config.level,
            "intensity": image_poison_config.intensity,
            "seed": image_poison_config.seed,
            "max_dimension": image_poison_config.max_dimension,
            "jpeg_quality": image_poison_config.jpeg_quality,
            "edge_only": image_poison_config.edge_only,
        });
        let site_image_poison_key = format!("site_image_poison_config:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&site_image_poison_json) {
            record_store.store_and_announce(site_image_poison_key, bytes, 3600);
        }

        let minification_json = serde_json::json!({
            "enabled": static_config.enable_minification,
            "enable_html": static_config.enable_html_minification,
            "enable_css": static_config.enable_css_minification,
            "enable_js": static_config.enable_js_minification,
        });
        let minification_key = format!("upstream_minification:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&minification_json) {
            record_store.store_and_announce(minification_key, bytes, 3600);
        }

        let compression_json = serde_json::json!({
            "enabled": static_config.enable_compression,
            "gzip_on_the_fly": static_config.gzip_on_the_fly,
            "gzip_level": static_config.gzip_level,
            "gzip_min_size": static_config.gzip_min_size,
            "gzip_types": static_config.gzip_types,
            "enable_brotli": static_config.enable_brotli,
            "brotli_level": static_config.brotli_level,
        });
        let compression_key = format!("upstream_compression:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&compression_json) {
            record_store.store_and_announce(compression_key, bytes, 3600);
        }

        if let Some(ref cache_config) = site_config.proxy.cache {
            let proxy_cache_prefs =
                crate::mesh::protocol::ProxyCachePreferences::from(cache_config);
            if let Ok(bytes) = serde_json::to_vec(&proxy_cache_prefs) {
                let key = format!("upstream_proxy_cache_preferences:{}", site_id);
                record_store.store_and_announce(key, bytes, 3600);
            }
        }

        tracing::debug!("Published transform config for site {} to DHT", site_id);
    }

    pub async fn get_edge_key(&self, edge_id: &str) -> Option<String> {
        if let Some(ref record_store) = self.record_store {
            let key = format!("edge_key:{}", edge_id);
            if let Some(record) = record_store.get_record(&key) {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                    return value
                        .get("public_key")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
        None
    }

    pub fn initialize_component_transports(transport_arc: Arc<Self>) {
        if let Some(ref rs) = transport_arc.record_store {
            rs.set_transport(transport_arc.clone());
        }
        if let Some(ref ti) = transport_arc.threat_intel {
            ti.set_transport(Arc::clone(&transport_arc));
        }
        transport_arc
            .org_key_manager
            .set_transport(transport_arc.clone());

        if let Some(ref bp) = transport_arc.backend_pool {
            let raft_client = Arc::new(crate::mesh::raft::client::RaftAwareClient::new(
                bp.clone(),
                transport_arc.clone(),
                transport_arc.config.clone(),
                transport_arc.record_store.clone(),
            ));

            if let Some(ref manager) = *transport_arc.edge_replica_manager.read() {
                let rc = raft_client.clone();
                let m = manager.clone();
                tokio::spawn(async move {
                    rc.set_edge_replica_manager(m).await;
                });
            }

            transport_arc
                .org_key_manager
                .set_raft_client(raft_client.clone());

            raft_client.start_reconciliation_loop();
        }

        let wasm_dist_manager = Arc::new(crate::mesh::wasm_dist::WasmDistManager::new());
        crate::mesh::wasm_dist::set_global_wasm_dist_manager(wasm_dist_manager);
    }

    pub fn check_global_rate_limit(&self) -> bool {
        let check = self.global_rate_limiter.check();
        let max_per_second = self.config.routing.mesh_messages_per_sec;

        if check.current_per_second > max_per_second as u64 {
            tracing::warn!(
                "Global mesh rate limit exceeded: {} msg/s (limit: {})",
                check.current_per_second,
                max_per_second
            );
            return false;
        }

        self.global_rate_limiter.record();
        true
    }

    pub fn is_global_rate_limit_exceeded(&self) -> bool {
        let check = self.global_rate_limiter.check();
        let max_per_second = self.config.routing.mesh_messages_per_sec;
        check.current_per_second > max_per_second as u64
    }

    pub fn is_message_seen(&self, message_id: &str) -> bool {
        self.seen_messages.read().contains_key(message_id)
    }

    pub fn mark_message_seen(&self, message_id: &str) {
        let mut cache = self.seen_messages.write();
        cache.insert(message_id.to_string(), Instant::now());
    }

    pub fn get_message_cache_size(&self) -> usize {
        self.seen_messages.read().len()
    }

    pub fn clean_expired_messages(&self) {
        let mut cache = self.seen_messages.write();
        let now = Instant::now();
        cache
            .iter()
            .filter(|(_, time)| now.duration_since(**time).as_secs() > 300)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|k| {
                cache.remove(&k);
            });
    }

    pub fn set_runtime(&mut self, runtime: Arc<QuicRuntime>) {
        self.runtime = Some(runtime);
    }

    pub fn set_serverless_manager(
        &self,
        manager: Arc<crate::serverless::manager::ServerlessManager>,
    ) {
        *self.serverless_manager.write() = Some(manager);
    }

    pub(crate) async fn update_threat_intel_global_nodes(&self) {
        if let Some(ref threat_intel) = self.threat_intel {
            let global_nodes = self.topology.get_global_nodes_as_peer_info().await;
            threat_intel.update_global_nodes(global_nodes);
        }
    }

    pub fn get_quic_port(&self) -> Option<u16> {
        if let Some(ref runtime) = self.runtime {
            runtime.local_port()
        } else {
            Some(self.config.port)
        }
    }

    pub async fn get_actual_quic_port(&self) -> Option<u16> {
        if let Some(ref runtime) = self.runtime {
            if let Some(addr) = runtime.local_addr().await {
                return Some(addr.port());
            }
            return runtime.local_port();
        }
        self.config.quic_port.or(Some(self.config.port))
    }

    pub fn get_bind_addresses(&self) -> Vec<String> {
        if let Some(ref addr) = self.config.bind_address {
            vec![addr.clone()]
        } else {
            vec!["0.0.0.0".to_string()]
        }
    }

    pub async fn send_datagram_to_peer(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let peer = self
            .peer_connections
            .get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let encoded = message
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        peer.connection
            .send_datagram(encoded.into())
            .map_err(|e| MeshTransportError::SendFailed(format!("Datagram send failed: {}", e)))?;

        tracing::debug!("Sent datagram to peer {}: {:?}", peer_id, message);
        Ok(())
    }

    pub async fn broadcast_site_config_to_origins(
        &self,
        site_id: &str,
        config_json: &str,
        config_version: u64,
        proxy_cache_preferences: Option<crate::mesh::protocol::ProxyCachePreferences>,
    ) -> Result<(usize, usize), String> {
        let current_node_id = self.topology.node_id().to_string();

        let is_origin = {
            let origins = self.topology.find_all_origins_for_site(site_id).await;
            origins.contains(&current_node_id)
        };

        if !is_origin {
            tracing::debug!(
                "Node {} is not an origin for site {}, skipping broadcast",
                current_node_id,
                site_id
            );
            return Ok((0, 0));
        }

        let origins = self.topology.find_all_origins_for_site(site_id).await;

        let mut success_count = 0;
        let mut fail_count = 0;

        let target_origins: Vec<String> = origins
            .into_iter()
            .filter(|id| id != &current_node_id)
            .collect();

        let proxy_cache_prefs = proxy_cache_preferences.clone();
        let mut futures = FuturesUnordered::new();
        for origin_node_id in &target_origins {
            let transport = self.clone();
            let site_id = site_id.to_string();
            let config_json = config_json.to_string();
            let current_node_id = current_node_id.clone();
            let node_id = origin_node_id.clone();
            let signer = self.mesh_signer.clone();
            let config_version = config_version;
            let proxy_cache_prefs = proxy_cache_prefs.clone();
            futures.push(async move {
                let request_id = MeshMessage::generate_nonce();
                let timestamp = MeshMessage::generate_timestamp();

                let (signature, signer_public_key) = if let Some(ref signer) = signer {
                    let msg = format!(
                        "{}:{}:{}:{}",
                        site_id,
                        config_version,
                        config_json.len(),
                        timestamp
                    );
                    (
                        signer.sign(msg.as_bytes()),
                        Some(signer.get_public_key().into()),
                    )
                } else {
                    (Vec::new(), None)
                };

                let message = MeshMessage::SiteConfigSync {
                    request_id,
                    site_id: site_id.clone().into(),
                    config_version,
                    config_json: config_json.clone().into(),
                    timestamp,
                    source_node_id: current_node_id.clone().into(),
                    signature,
                    signer_public_key,
                    proxy_cache_preferences: proxy_cache_prefs,
                };

                let result = transport.send_datagram_to_peer(&node_id, &message).await;
                (node_id, result)
            });
        }
        while let Some((node_id, result)) = futures.next().await {
            match result {
                Ok(_) => {
                    tracing::info!(
                        "Sent site config sync to origin {} for site {}",
                        node_id,
                        site_id
                    );
                    success_count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to send site config sync to origin {}: {}",
                        node_id,
                        e
                    );
                    fail_count += 1;
                }
            }
        }

        Ok((success_count, fail_count))
    }

    /// Send a route query using QUIC streams for reliable, ordered delivery
    /// This is faster than datagrams in lossy networks due to built-in retransmission
    pub async fn send_message_to_peer(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let peer = self
            .peer_connections
            .get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let (mut send_stream, recv_stream) = {
            let mut pool = peer.stream_pool.lock().await;
            pool.acquire().await
        }
        .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let encoded = message
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        {
            let mut pool = peer.stream_pool.lock().await;
            pool.release((send_stream, recv_stream));
        }

        tracing::debug!("Sent stream message to peer {}: {:?}", peer_id, message);
        Ok(())
    }

    const STREAM_RESPONSE_TIMEOUT_SECS: u64 = 30;

    /// Send a message to a peer and wait for a response on the same stream.
    /// This acquires a stream, writes the request, reads the response, then releases.
    /// On any failure (timeout, decode error, oversized response), the stream is NOT
    /// returned to the pool to prevent poisoning.
    pub async fn send_message_to_peer_with_response(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<Vec<u8>, MeshTransportError> {
        let peer = self
            .peer_connections
            .get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let (mut send_stream, mut recv_stream) = {
            let mut pool = peer.stream_pool.lock().await;
            pool.acquire().await
        }
        .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let encoded = message
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let timeout_duration = Duration::from_secs(Self::STREAM_RESPONSE_TIMEOUT_SECS);
        let result = tokio::time::timeout(timeout_duration, async {
            let mut len_buf = [0u8; 4];
            recv_stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| MeshTransportError::ReceiveFailed(format!("{:?}", e)))?;
            let resp_len = u32::from_be_bytes(len_buf) as usize;
            if resp_len > MAX_MESSAGE_SIZE {
                return Err(MeshTransportError::ReceiveFailed(
                    "Response too large".into(),
                ));
            }
            let mut response_buf = vec![0u8; resp_len];
            recv_stream
                .read_exact(&mut response_buf)
                .await
                .map_err(|e| MeshTransportError::ReceiveFailed(format!("{:?}", e)))?;
            Ok(response_buf)
        })
        .await;

        match result {
            Ok(Ok(response_buf)) => {
                {
                    let mut pool = peer.stream_pool.lock().await;
                    pool.release((send_stream, recv_stream));
                }
                tracing::debug!(
                    "Sent stream message to peer {} and received response: {:?}",
                    peer_id,
                    message
                );
                Ok(response_buf)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Stream response read failed for peer {}: {:?} - NOT returning stream to pool",
                    peer_id,
                    e
                );
                Err(e)
            }
            Err(_) => {
                tracing::warn!(
                    "Stream response timed out after {}s for peer {} - NOT returning stream to pool",
                    Self::STREAM_RESPONSE_TIMEOUT_SECS,
                    peer_id
                );
                Err(MeshTransportError::ReceiveFailed("Response timeout".into()))
            }
        }
    }

    /// Invoke a serverless function on a remote peer
    /// Returns a future that resolves to the invocation response
    pub async fn invoke_serverless_remote(
        &self,
        peer_id: &str,
        function_name: &str,
    ) -> Result<crate::mesh::protocol::ServerlessInvokeResponse, MeshTransportError> {
        let request = crate::mesh::protocol::ServerlessInvokeRequest::new(
            function_name.to_string(),
            self.config.node_id(),
        );

        let response_future = {
            let mut pending = self.pending_serverless_invocations.lock().await;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let key = format!("{}:{}", function_name, self.config.node_id());
            pending.insert(key, tx);
            rx
        };

        let msg = MeshMessage::ServerlessInvokeRequest(request);
        self.send_message_to_peer(peer_id, &msg).await?;

        tracing::debug!(
            "Sent ServerlessInvokeRequest for '{}' to peer {}",
            function_name,
            peer_id
        );

        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(30), response_future).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(MeshTransportError::ReceiveFailed(
                "Serverless invocation response channel closed".to_string(),
            )),
            Err(_) => {
                // Clean up pending invocation on timeout
                let mut pending = self.pending_serverless_invocations.lock().await;
                let key = format!("{}:{}", function_name, self.config.node_id());
                pending.remove(&key);
                Err(MeshTransportError::Timeout)
            }
        }
    }

    pub fn get_key_exchange_endpoint(&self) -> Option<String> {
        if !self.config.global_node.key_exchange_enabled {
            return None;
        }

        let port = self.config.global_node.key_exchange_port;

        // Try to get the first non-loopback IP for the endpoint
        match crate::utils::get_first_non_loopback_ip() {
            Ok(ip) => Some(format!("https://{}:{}", ip, port)),
            Err(_) => {
                // Fallback to bind address if we can't determine our IP
                let bind_address = self.config.bind_address.as_deref().unwrap_or("0.0.0.0");
                Some(format!("https://{}:{}", bind_address, port))
            }
        }
    }

    pub async fn update_key_exchange_endpoint(&self) {
        if !self.config.role.is_global() {
            return;
        }

        let genesis_key = match self.config.genesis_key() {
            Some(g) => g,
            None => {
                tracing::warn!("No genesis key configured - cannot update key exchange endpoint");
                return;
            }
        };

        let timestamp = crate::utils::safe_unix_timestamp();

        let key_exchange_endpoint = self.get_key_exchange_endpoint();

        // Include endpoint in signable message
        let endpoint_str = key_exchange_endpoint.clone().unwrap_or_default();
        let signable = format!(
            "{}:{}:{}:{}:{}",
            self.config.node_id(),
            self.config.global_node_key.as_deref().unwrap_or(""),
            crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange as u8,
            timestamp,
            endpoint_str
        );

        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign key exchange endpoint update");
                return;
            }
        };

        // Update local DHT
        if let Some(ref record_store) = self.record_store {
            let key = format!("global_node_key:{}", self.config.node_id());
            let value = serde_json::json!({
                "node_id": self.config.node_id(),
                "public_key": self.config.global_node_key.clone().unwrap_or_default(),
                "key_exchange_endpoint": key_exchange_endpoint,
                "announced_at": timestamp,
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key, bytes, 86400);
            }
        }

        // Broadcast update
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: self.config.node_id().into(),
            public_key: self
                .config
                .global_node_key
                .clone()
                .unwrap_or_default()
                .into(),
            action: crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange,
            timestamp,
            signature,
            key_exchange_endpoint: key_exchange_endpoint.map(|s| s.into()),
        };

        let _ = self
            .broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::GLOBAL))
            .await;
        tracing::info!(
            "Updated key exchange endpoint for global node {}",
            self.config.node_id()
        );
    }

    pub(crate) async fn handle_ping(&self, from_peer: &str, request_id: &str) {
        tracing::debug!("Received Ping from {}", from_peer);

        let response = crate::mesh::protocol::MeshMessage::Pong {
            request_id: request_id.into(),
            node_id: self.config.node_id().into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send Pong to {}: {}", from_peer, e);
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn handle_pong(&self, from_peer: &str, _request_id: &str, node_id: &str) {
        tracing::debug!("Received Pong from {}", from_peer);

        let Some(ref routing_manager) = self.routing_manager else {
            return;
        };

        routing_manager.update_peer_latency(node_id, 0).await;
    }

    #[cfg(feature = "dns")]
    pub async fn start(&self) -> Result<(), MeshTransportError> {
        {
            let mut running = self.running.write();
            if *running {
                return Ok(());
            }
            *running = true;
        }

        let (shutdown_tx, _) = broadcast::channel(1);
        {
            let mut tx = self.shutdown_tx.write();
            *tx = Some(shutdown_tx.clone());
        }

        if self.config.role.is_global() {
            let transport_for_attest = Arc::new(self.clone_for_maintenance());
            tokio::spawn(async move {
                let node_id = transport_for_attest.config.node_id().to_string();

                // Allow some time for DHT to initialize before self-attesting
                tokio::time::sleep(Duration::from_secs(5)).await;

                transport_for_attest
                    .attest_capability(&node_id, "waf")
                    .await;
                transport_for_attest
                    .attest_capability(&node_id, "threat_intel")
                    .await;

                // For simplicity, we just self-attest DNS as well since global nodes act as DNS root
                transport_for_attest
                    .attest_capability(&node_id, "dns")
                    .await;

                tracing::info!("Global node '{}' self-attested capabilities", node_id);
            });
        }

        // PoW refresh: periodically refresh the cached PoW nonce before TTL expires
        // Started early since config is moved later in this function
        if self.config.role.is_edge() {
            let pow_config = self.config.clone();
            tokio::spawn(async move {
                let refresh_interval = Duration::from_secs(2700); // 45 minutes (half of 1hr TTL)
                let mut interval = tokio::time::interval(refresh_interval);
                loop {
                    interval.tick().await;
                    tracing::debug!("Refreshing PoW nonce cache");
                    if let Some(ref pk_hex) = pow_config.signing_public_key() {
                        use base64::Engine;
                        if let Ok(pk_bytes) =
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_hex)
                        {
                            if let Some(nonce) =
                                crate::mesh::dht::routing::node_id::NodeId::find_pow_nonce(
                                    &pk_bytes,
                                )
                            {
                                pow_config.set_cached_pow_nonce(nonce);
                                tracing::info!("Refreshed PoW nonce: {}", nonce);
                            } else {
                                tracing::warn!("Failed to compute new PoW nonce during refresh");
                            }
                        }
                    }
                }
            });
        }

        // ML-KEM key rotation: periodically rotate stale sessions for forward secrecy
        if let Some(ref mlkem_manager) = self.mlkem_session_manager {
            let mlkem_manager = mlkem_manager.clone();
            let rotation_interval = mlkem_manager.config().rotation_interval;
            let session_rotation_transport = Arc::new(self.clone_for_maintenance());
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(rotation_interval);
                loop {
                    interval.tick().await;
                    tracing::debug!("Running ML-KEM key rotation");
                    let rotated = mlkem_manager.rotate_stale_sessions();
                    if !rotated.is_empty() {
                        tracing::info!("Rotated {} ML-KEM sessions", rotated.len());
                        for session in &rotated {
                            if let Some((sid, kv, entropy)) =
                                mlkem_manager.prepare_session_rotation(&session.id)
                            {
                                let msg = MeshMessage::SessionRotate {
                                    session_id: sid.clone().into(),
                                    peer_id: session.peer_id.clone().into(),
                                    key_version: kv,
                                    peer_entropy: entropy,
                                    timestamp: crate::utils::current_timestamp(),
                                };
                                if let Err(e) = session_rotation_transport
                                    .send_message_to_peer(&session.peer_id, &msg)
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to send SessionRotate to {}: {}",
                                        session.peer_id,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    let cleaned = mlkem_manager.cleanup_expired();
                    if cleaned > 0 {
                        tracing::debug!("Cleaned up {} expired ML-KEM sessions", cleaned);
                    }
                }
            });
        }

        let config = self.config.clone();
        let topology = self.topology.clone();
        let peer_connections = self.peer_connections.clone();
        let shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            Self::mesh_maintenance_loop(config, topology, peer_connections, shutdown_rx).await;
        });

        let datagram_shutdown = shutdown_tx.subscribe();
        let peer_connections_for_datagram = self.peer_connections.clone();
        tokio::spawn(async move {
            Self::datagram_listener_loop(peer_connections_for_datagram, datagram_shutdown).await;
        });

        if !self.config.seeds.is_empty() {
            self.bootstrap_from_seeds().await?;
        }

        if !self.config.peers.is_empty() {
            self.connect_to_peers().await?;
        }

        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                self.dht_bootstrap_from_seeds(rm.clone()).await?;
            }
        }

        let connection_config = self.config.connection.clone();
        let transport_for_maintenance = Arc::new(self.clone_for_maintenance());

        if connection_config.min_peer_connections > 0 {
            let maintenance_transport = transport_for_maintenance.clone();
            let maintenance_interval = Duration::from_secs(30);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(maintenance_interval);
                loop {
                    interval.tick().await;
                    maintenance_transport.maintain_connections().await;
                    maintenance_transport.perform_auto_slash().await;
                }
            });

            let health_transport = transport_for_maintenance.clone();
            let health_interval = Duration::from_secs(connection_config.health_check_interval_secs);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(health_interval);
                loop {
                    interval.tick().await;
                    let peers: Vec<String> = health_transport
                        .peer_connections
                        .iter()
                        .map(|e| e.value().node_id.clone())
                        .collect();
                    for peer_id in peers {
                        health_transport.perform_health_check(&peer_id).await;
                    }
                }
            });

            // Proactive cache warming: periodically query popular routes from peers
            let cache_warm_transport = transport_for_maintenance.clone();
            let cache_warm_interval = Duration::from_secs(60);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(cache_warm_interval);
                loop {
                    interval.tick().await;
                    cache_warm_transport.proactive_cache_warm().await;
                }
            });

            // DHT cache resync: periodically refresh edge node cache from global nodes
            // Uses adaptive interval from record_store (starts at 30s, backs off to 1 hour)
            let dht_resync_transport = transport_for_maintenance.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    dht_resync_transport.dht_cache_resync().await;
                }
            });

            // Load reporter: periodically send local load metrics to mesh peers
            let load_report_transport = transport_for_maintenance.clone();
            let load_report_interval = Duration::from_secs(60);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(load_report_interval);
                loop {
                    interval.tick().await;
                    load_report_transport.send_load_report_to_peers().await;
                }
            });

            // Global node heartbeat: publish heartbeat every 30s for liveness monitoring
            // Only global nodes publish heartbeats; TTL is 90s (3x interval)
            let heartbeat_transport = transport_for_maintenance.clone();
            let heartbeat_interval = Duration::from_secs(30);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(heartbeat_interval);
                loop {
                    interval.tick().await;
                    heartbeat_transport.publish_global_node_heartbeat().await;
                }
            });
        }

        if let Some(ref runtime) = self.runtime {
            let incoming = runtime
                .start_server()
                .await
                .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;
            let transport = Arc::new(self.clone_for_maintenance());
            let shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                Self::mesh_accept_loop(transport, incoming, shutdown_rx).await;
            });
        }

        tracing::info!("Mesh transport started");
        Ok(())
    }

    async fn mesh_accept_loop(
        self: Arc<MeshTransport>,
        mut incoming: mpsc::Receiver<crate::tunnel::quic::runtime::IncomingConnection>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                Some(incoming_conn) = incoming.recv() => {
                    let transport = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = transport.handle_incoming_peer_connection(incoming_conn).await {
                            tracing::warn!("Failed to handle incoming peer connection: {}", e);
                        }
                    });
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Mesh accept loop shutting down");
                    break;
                }
            }
        }
    }

    async fn handle_incoming_peer_connection(
        &self,
        incoming: crate::tunnel::quic::runtime::IncomingConnection,
    ) -> Result<(), MeshTransportError> {
        let remote_addr = incoming.remote_addr;
        let connection = incoming.connection;

        tracing::debug!("Accepted incoming connection from {}", remote_addr);

        let (mut send_stream, mut recv_stream) = connection
            .accept_bi()
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(format!("Accept bi failed: {}", e)))?;

        let mut len_buf = [0u8; 4];
        recv_stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(format!("Read length failed: {}", e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE || len == 0 {
            return Err(MeshTransportError::ReceiveFailed(format!(
                "Invalid message length: {} (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }
        let mut hello_buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut hello_buf)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(format!("Read hello failed: {}", e)))?;

        let hello_msg = MeshMessage::decode(&hello_buf).ok_or_else(|| {
            MeshTransportError::ReceiveFailed("Failed to decode Hello message".to_string())
        })?;

        let (
            peer_node_id,
            peer_role,
            peer_capabilities,
            peer_upstreams,
            peer_quic_port,
            peer_wireguard_port,
            trusted_status,
        ) = match hello_msg {
            MeshMessage::Hello {
                version,
                node_id,
                role,
                capabilities,
                upstreams,
                auth_token,
                network_id,
                global_node_key,
                timestamp,
                nonce: _,
                is_trusted,
                quic_port,
                wireguard_port,
                public_key,
                pow_nonce,
                pow_public_key,
                member_certificate,
                org_public_key,
            } => {
                if version != MESH_MESSAGE_VERSION {
                    return Err(MeshTransportError::VersionMismatch {
                        expected: MESH_MESSAGE_VERSION,
                        got: version,
                    });
                }

                if let Some(ref expected_token) = auth_token {
                    if !self
                        .auth_keys
                        .read()
                        .values()
                        .any(|k| k.as_slice() == expected_token.as_bytes())
                    {
                        tracing::warn!(
                            "Authentication failed for node {}: invalid auth token",
                            node_id
                        );
                        return Err(MeshTransportError::AuthFailed(
                            "Invalid auth token".to_string(),
                        ));
                    }
                }

                if let Some(ref our_network) = self.config.network_id {
                    if let Some(ref peer_network) = network_id {
                        if peer_network.as_str() != our_network.as_str() {
                            tracing::warn!("Network ID mismatch from {}", node_id);
                            return Err(MeshTransportError::AuthFailed(
                                "Network ID mismatch".to_string(),
                            ));
                        }
                    }
                }

                let authorized_keys: Vec<String> = self
                    .config
                    .seeds
                    .iter()
                    .filter_map(|seed| seed.public_key.clone())
                    .collect();
                let peer_pk = public_key.as_ref().map(|pk| pk.as_str());
                let peer_sig = global_node_key.as_ref().map(|sk| sk.as_str());
                let global_node_att_key = if role.is_origin() {
                    public_key.as_ref().map(|pk| pk.as_str())
                } else {
                    None
                };
                let global_node_att_sig = if role.is_origin() {
                    global_node_key.as_ref().map(|sk| sk.as_str())
                } else {
                    None
                };
                if let Err(e) = crate::mesh::peer_auth::validate_peer_role(
                    &role,
                    &authorized_keys,
                    &node_id,
                    peer_pk,
                    peer_sig,
                    timestamp.unwrap_or(0),
                    300,
                    self.revocation_list.as_ref().map(|r| r.as_ref()),
                    global_node_att_key,
                    global_node_att_sig,
                    pow_nonce,
                    pow_public_key.as_ref().map(|s| s.as_str()),
                    member_certificate.as_ref(),
                    org_public_key.as_ref(),
                ) {
                    tracing::warn!("Node verification failed for {}: {}", node_id, e);
                    return Err(MeshTransportError::AuthFailed(e));
                }

                let upstreams_map: HashMap<String, crate::mesh::protocol::UpstreamInfo> =
                    upstreams.into_iter().collect();

                (
                    node_id.to_string(),
                    role,
                    capabilities,
                    upstreams_map,
                    quic_port,
                    wireguard_port,
                    is_trusted,
                )
            }
            _ => {
                return Err(MeshTransportError::UnexpectedMessage);
            }
        };

        let session_id = uuid::Uuid::new_v4().to_string();
        let quic_port = self.get_quic_port().map(|p| p as u32);
        let wireguard_port = None;
        let upstreams = self.topology.get_local_upstreams().await;
        let upstreams_internal: HashMap<String, crate::mesh::protocol::UpstreamInfo> = upstreams
            .into_iter()
            .map(|u| (u.upstream_id.clone(), u))
            .collect();

        let hello_ack = MeshMessage::HelloAck {
            version: MESH_MESSAGE_VERSION,
            node_id: self.config.node_id().into(),
            role: self.config.role,
            session_id: session_id.clone().into(),
            capabilities: crate::mesh::protocol::MeshCapabilities::from_config(
                &self.config,
                self.config.role,
            ),
            upstreams: upstreams_internal.clone(),
            auth_token: None,
            network_id: self.config.network_id.clone().map(|s| s.into()),
            global_node_key: None,
            timestamp: Some(MeshMessage::generate_timestamp()),
            nonce: None,
            is_trusted: self.config.is_trusted_node(),
            quic_port,
            wireguard_port,
            public_key: self.config.signing_public_key().map(|s| s.into()),
            member_certificate: {
                let (cert, _) = self.get_org_auth_data();
                cert
            },
            org_public_key: {
                let (_, key) = self.get_org_auth_data();
                key
            },
        };

        let encoded = hello_ack
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let peer_info = crate::mesh::protocol::MeshPeerInfo {
            node_id: peer_node_id.clone(),
            address: remote_addr.to_string(),
            role: peer_role,
            capabilities: peer_capabilities.clone(),
            is_global: peer_role.is_global(),
            latency_ms: None,
            upstreams: peer_upstreams.keys().cloned().collect(),
            is_trusted: trusted_status,
            quic_port: peer_quic_port,
            wireguard_port: peer_wireguard_port,
            advertised_port: peer_quic_port.or(peer_wireguard_port),
            dns_serving_healthy: peer_capabilities.can_serve_dns,
        };

        let peer_connection = crate::mesh::transport_types::MeshPeerConnection {
            node_id: peer_node_id.clone(),
            address: remote_addr.to_string(),
            connection: connection.clone(),
            session_id: session_id.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            role: peer_role,
            upstreams: peer_upstreams.keys().cloned().collect(),
            is_trusted: trusted_status,
            replay_protection: Arc::new(tokio::sync::RwLock::new(
                crate::mesh::protocol::ReplayProtection::new(),
            )),
            stream_pool: Arc::new(tokio::sync::Mutex::new(
                crate::mesh::transport_types::MeshStreamPool::new(Some(connection.clone())),
            )),
        };

        self.topology
            .add_peer(
                peer_info.clone(),
                crate::mesh::topology::PeerStatus::Healthy,
            )
            .await;
        self.peer_connections
            .insert(session_id.clone(), peer_connection);

        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                self.dht_on_peer_connected(&peer_node_id, &remote_addr.to_string(), peer_role)
                    .await;
            }
        }

        tracing::info!(
            "Accepted mesh peer connection: {} ({})",
            peer_node_id,
            remote_addr
        );

        let transport = self.clone();
        let topo = self.topology.clone();
        tokio::spawn(async move {
            transport
                .peer_message_loop(session_id, peer_node_id, connection, topo)
                .await;
        });

        Ok(())
    }

    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.write().take() {
            let _ = tx.send(());
        }

        for entry in self.peer_connections.iter() {
            entry
                .value()
                .connection
                .close(0u32.into(), b"Mesh shutdown");
        }
        self.peer_connections.clear();

        let mut running = self.running.write();
        *running = false;

        tracing::info!("Mesh transport stopped");
    }

    pub(crate) async fn bootstrap_from_seeds(&self) -> Result<(), MeshTransportError> {
        let verified_seeds = self.config.get_verified_seeds();

        if verified_seeds.is_empty() {
            tracing::warn!("No verified seeds available for network");
            return Err(MeshTransportError::NoSeedsAvailable);
        }

        for seed in &verified_seeds {
            tracing::info!("Attempting to connect to verified seed: {}", seed.address);

            let peer_config = MeshPeerConfig {
                address: seed.address.clone(),
                auth_token: seed.public_key.clone(),
            };
            match self.connect_to_peer(&peer_config).await {
                Ok(peer_info) => {
                    tracing::info!("Connected to seed node: {}", seed.address);

                    if let Err(e) = self.request_seed_list(&peer_info.node_id).await {
                        tracing::warn!("Failed to request seed list from {}: {}", seed.address, e);
                    }
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to seed {}: {}", seed.address, e);
                }
            }
        }
        Err(MeshTransportError::NoSeedsAvailable)
    }

    pub(crate) async fn connect_to_peer(
        &self,
        peer_config: &MeshPeerConfig,
    ) -> Result<MeshPeerConnection, MeshTransportError> {
        if !self.check_rate_limit() {
            return Err(MeshTransportError::RateLimited);
        }

        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MeshTransportError::RuntimeNotSet)?;

        let server_name = peer_config
            .address
            .split(':')
            .next()
            .unwrap_or(&peer_config.address);

        let quic_conn = runtime
            .connect_to_peer(&peer_config.address, server_name)
            .await
            .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;

        let connection = quic_conn
            .connection
            .clone()
            .ok_or_else(|| MeshTransportError::ConnectionFailed("No connection".to_string()))?;

        // TOFU: Verify seed peer certificate fingerprint
        {
            let cert_mgr = self.cert_manager.read();
            if cert_mgr.is_tofu_enabled() {
                if let Some(peer_cert_any) = connection.peer_identity() {
                    if let Some(peer_cert) =
                        peer_cert_any.downcast_ref::<rustls_pki_types::CertificateDer<'_>>()
                    {
                        let fingerprint =
                            crate::mesh::cert::MeshCertManager::compute_cert_fingerprint(peer_cert);
                        let addr = &peer_config.address;
                        if let Err(e) = cert_mgr.verify_seed_fingerprint(addr, &fingerprint) {
                            tracing::warn!(
                                "TOFU fingerprint verification failed for {}: {}",
                                addr,
                                e
                            );
                            return Err(MeshTransportError::AuthFailed(e));
                        }
                    }
                }
            }
        }

        let (mut send_stream, mut recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;

        let node_id = self.config.node_id();
        let local_upstreams = self.topology.get_local_upstreams().await;

        let upstreams: HashMap<String, UpstreamInfo> = local_upstreams
            .into_iter()
            .map(|u| (u.upstream_id.clone(), u))
            .collect();

        let auth_token = peer_config.auth_token.clone();

        let quic_port = self.get_actual_quic_port().await.map(|p| p as u32);
        let wireguard_port = None;

        let is_edge = self.config.role.is_edge();

        let (pow_nonce, pow_public_key) = if is_edge {
            if let Some(ref pk_hex) = self.config.signing_public_key() {
                if let Some(cached_nonce) = self.config.get_cached_pow_nonce() {
                    (Some(cached_nonce), Some(pk_hex.clone().into()))
                } else {
                    use base64::Engine;
                    if let Ok(pk_bytes) =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_hex)
                    {
                        if let Some(nonce) =
                            crate::mesh::dht::routing::node_id::NodeId::find_pow_nonce(&pk_bytes)
                        {
                            tracing::debug!("Computed PoW nonce for edge node: {}", nonce);
                            self.config.set_cached_pow_nonce(nonce);
                            (Some(nonce), Some(pk_hex.clone().into()))
                        } else {
                            tracing::error!(
                                "Failed to find PoW nonce for edge node - cannot connect"
                            );
                            return Err(MeshTransportError::ConnectionFailed(
                                "Failed to compute PoW".to_string(),
                            ));
                        }
                    } else {
                        return Err(MeshTransportError::ConnectionFailed(
                            "Invalid public key format".to_string(),
                        ));
                    }
                }
            } else {
                return Err(MeshTransportError::ConnectionFailed(
                    "No signing key configured".to_string(),
                ));
            }
        } else {
            (None, None)
        };

        // Generate Ed25519 signature for global node authentication
        let global_node_auth_sig = if self.config.role.is_global() {
            if let Some(sk) = self.config.signing_key() {
                if sk.len() == 32 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(sk);
                    match crate::mesh::peer_auth::generate_global_node_auth(
                        &self.config.node_id(),
                        &key_bytes,
                    ) {
                        Ok((sig, _ts)) => Some(sig.into()),
                        Err(e) => {
                            tracing::warn!("Failed to generate global node auth signature: {}", e);
                            None
                        }
                    }
                } else {
                    tracing::warn!("Signing key has invalid length for Ed25519: {}", sk.len());
                    None
                }
            } else {
                tracing::warn!("No signing key available for global node authentication");
                None
            }
        } else {
            None
        };

        let hello = MeshMessage::Hello {
            version: MESH_MESSAGE_VERSION,
            node_id: node_id.clone().into(),
            role: self.config.role,
            capabilities: crate::mesh::protocol::MeshCapabilities::from_config(
                &self.config,
                self.config.role,
            ),
            upstreams,
            auth_token: auth_token.clone().map(|s| s.into()),
            network_id: self.config.network_id.clone().map(|s| s.into()),
            global_node_key: global_node_auth_sig,
            timestamp: Some(MeshMessage::generate_timestamp()),
            nonce: Some(MeshMessage::generate_nonce()),
            is_trusted: self.config.is_trusted_node(),
            quic_port,
            wireguard_port,
            public_key: self.config.signing_public_key().map(|s| s.into()),
            pow_nonce,
            pow_public_key,
            member_certificate: {
                let (cert, _) = self.get_org_auth_data();
                cert
            },
            org_public_key: {
                let (_, key) = self.get_org_auth_data();
                key
            },
        };

        let encoded = hello
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let mut len_buf = [0u8; 4];
        recv_stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(MeshTransportError::ReceiveFailed(format!(
                "Response too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }
        let mut response_buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut response_buf)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;

        let response = MeshMessage::decode(&response_buf).ok_or_else(|| {
            MeshTransportError::ReceiveFailed("Failed to decode response".to_string())
        })?;

        let (session_id, peer_info) = match response {
            MeshMessage::HelloAck {
                version,
                node_id,
                role,
                session_id,
                capabilities: peer_capabilities,
                upstreams,
                auth_token: resp_token,
                network_id: resp_network_id,
                global_node_key: resp_global_key,
                timestamp: resp_timestamp,
                nonce: _,
                is_trusted: _,
                quic_port: peer_quic_port,
                wireguard_port: peer_wireguard_port,
                public_key: peer_public_key,
                member_certificate,
                org_public_key,
            } => {
                if let Some(ref pk) = peer_public_key {
                    use base64::Engine;
                    if let Ok(pk_bytes) =
                        base64::engine::general_purpose::STANDARD.decode(pk.as_str())
                    {
                        let expected_node_id =
                            crate::mesh::dht::routing::node_id::NodeId::from_public_key(&pk_bytes);
                        let claimed_node_id =
                            crate::mesh::dht::routing::node_id::NodeId::from_node_id_string(
                                node_id.as_str(),
                            );
                        if expected_node_id != claimed_node_id {
                            tracing::warn!(
                                "Node ID mismatch: peer claimed {} but their public key derives {}",
                                node_id,
                                expected_node_id
                            );
                            return Err(MeshTransportError::AuthFailed(
                                "Node ID does not match public key".to_string(),
                            ));
                        }
                    }
                } else {
                    tracing::warn!("Node {} did not provide public key in handshake", node_id);
                    return Err(MeshTransportError::AuthFailed(
                        "Public key is required for authentication".to_string(),
                    ));
                }

                let is_genesis_org_member = {
                    let org_mgr = self.org_manager.read();
                    let genesis_org_id = org_mgr
                        .get_genesis_org_id()
                        .cloned()
                        .unwrap_or_else(|| self.config.node_identity.genesis_org_id());
                    org_mgr.is_member(&genesis_org_id, &node_id)
                };
                let trusted_status = role.is_global() || is_genesis_org_member;

                if !trusted_status {
                    if let Some(ref stake_mgr) = self.stake_manager {
                        let config = stake_mgr.get_config();
                        let min_stake = config.min_stake_for_routing;
                        let strict_mode = config.strict_mode;
                        let node_id_str = node_id.to_string();

                        if !stake_mgr.can_be_in_routing(&node_id_str) {
                            if strict_mode {
                                tracing::warn!("Node {} rejected: insufficient stake for routing (strict mode, min: {})", node_id_str, min_stake);
                                return Err(MeshTransportError::AuthFailed(
                                    "Insufficient stake for mesh participation".to_string(),
                                ));
                            }

                            tracing::warn!("Auto-registering new node {} with zero reputation for grace period (non-strict mode). Node has NO routing privileges until stake verified.", node_id_str);
                            stake_mgr.register_node(node_id_str.clone(), 0, role, None);

                            tracing::warn!(
                                "Node {} registered with zero reputation - routing access disabled until stake verification",
                                node_id_str
                            );
                        }
                    }
                }

                tracing::debug!(
                    "Peer {} ports - quic: {:?}, wireguard: {:?}",
                    node_id,
                    peer_quic_port,
                    peer_wireguard_port
                );

                if version != MESH_MESSAGE_VERSION {
                    return Err(MeshTransportError::VersionMismatch {
                        expected: MESH_MESSAGE_VERSION,
                        got: version,
                    });
                }

                if let Some(ref expected_token) = auth_token {
                    match &resp_token {
                        Some(resp_t) if resp_t.as_str() == expected_token.as_str() => {}
                        _ => {
                            tracing::warn!("Authentication failed for node {}", node_id);
                            return Err(MeshTransportError::AuthFailed(
                                "Invalid auth token".to_string(),
                            ));
                        }
                    }
                }

                if let Some(ref our_network) = self.config.network_id {
                    if let Some(ref peer_network) = resp_network_id {
                        if peer_network.as_str() != our_network.as_str() {
                            tracing::warn!(
                                "Network ID mismatch: peer {} is on network {} but we are on {}",
                                node_id,
                                peer_network,
                                our_network
                            );
                            return Err(MeshTransportError::AuthFailed(
                                "Network ID mismatch".to_string(),
                            ));
                        }
                    }
                }

                let authorized_keys: Vec<String> = self
                    .config
                    .seeds
                    .iter()
                    .filter_map(|seed| seed.public_key.clone())
                    .collect();
                let peer_pk = peer_public_key.as_ref().map(|pk| pk.as_str());
                let peer_sig = resp_global_key.as_ref().map(|sk| sk.as_str());
                let global_node_att_key = if role.is_origin() {
                    peer_public_key.as_ref().map(|pk| pk.as_str())
                } else {
                    None
                };
                let global_node_att_sig = if role.is_origin() {
                    resp_global_key.as_ref().map(|sk| sk.as_str())
                } else {
                    None
                };
                if let Err(e) = crate::mesh::peer_auth::validate_peer_role(
                    &role,
                    &authorized_keys,
                    &node_id,
                    peer_pk,
                    peer_sig,
                    resp_timestamp.unwrap_or(0),
                    300,
                    self.revocation_list.as_ref().map(|r| r.as_ref()),
                    global_node_att_key,
                    global_node_att_sig,
                    None,
                    None,
                    member_certificate.as_ref(),
                    org_public_key.as_ref(),
                ) {
                    tracing::warn!("Node Ed25519 verification failed for {}: {}", node_id, e);
                    return Err(MeshTransportError::AuthFailed(e));
                }

                let upstreams: Vec<String> = upstreams.keys().cloned().collect();

                let peer_capabilities = peer_capabilities;
                let dns_serving_healthy = peer_capabilities.can_serve_dns;

                let peer_connection = MeshPeerConnection {
                    node_id: node_id.to_string(),
                    address: peer_config.address.clone(),
                    connection: connection.clone(),
                    session_id: session_id.to_string(),
                    connected_at: Instant::now(),
                    last_seen: Instant::now(),
                    role,
                    upstreams: upstreams.clone(),
                    is_trusted: trusted_status,
                    replay_protection: Arc::new(tokio::sync::RwLock::new(
                        crate::mesh::protocol::ReplayProtection::new(),
                    )),
                    stream_pool: Arc::new(tokio::sync::Mutex::new(MeshStreamPool::new(Some(
                        connection.clone(),
                    )))),
                };

                self.topology
                    .add_peer(
                        MeshPeerInfo {
                            node_id: node_id.to_string(),
                            address: peer_config.address.clone(),
                            role,
                            capabilities: peer_capabilities,
                            is_global: role.is_global(),
                            latency_ms: None,
                            upstreams: upstreams.clone(),
                            is_trusted: trusted_status,
                            quic_port: peer_quic_port,
                            wireguard_port: peer_wireguard_port,
                            advertised_port: peer_quic_port.or(peer_wireguard_port),
                            dns_serving_healthy,
                        },
                        PeerStatus::Healthy,
                    )
                    .await;

                (session_id, peer_connection)
            }
            MeshMessage::Error { code, message } => {
                return Err(MeshTransportError::PeerError {
                    code,
                    message: message.to_string(),
                });
            }
            _ => {
                return Err(MeshTransportError::UnexpectedMessage);
            }
        };

        let peer_node_id = peer_info.node_id.clone();
        let peer_address = peer_info.address.clone();
        let peer_role = peer_info.role;
        let peer_info_return = peer_info.clone();
        self.peer_connections
            .insert(session_id.to_string(), peer_info);

        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                self.dht_on_peer_connected(&peer_node_id, &peer_address, peer_role)
                    .await;
            }
        }

        // Preflight: query the new peer for their known routes to warm our cache
        let transport = self.clone();
        let peer_node_id_for_preflight = peer_node_id.clone();
        tokio::spawn(async move {
            if let Err(e) = transport
                .preflight_peer_routes(&peer_node_id_for_preflight)
                .await
            {
                tracing::debug!(
                    "Preflight routes from {}: {}",
                    peer_node_id_for_preflight,
                    e
                );
            }
        });

        let transport = self.clone();
        let conn = connection;
        let topo = self.topology.clone();
        let peer_node_id_for_loop = peer_node_id.clone();
        tokio::spawn(async move {
            transport
                .peer_message_loop(session_id.to_string(), peer_node_id_for_loop, conn, topo)
                .await;
        });

        tracing::info!(
            "Established mesh peer connection: {} ({})",
            peer_node_id,
            peer_address
        );

        Ok(peer_info_return)
    }

    pub async fn send_route_query(
        &self,
        upstream_id: &str,
    ) -> Result<RouteQueryResult, MeshTransportError> {
        if let Some(cached) = self.topology.get_cached_route(upstream_id).await {
            tracing::debug!(
                "Using cached route for {}: {} ({} hops)",
                upstream_id,
                cached.0,
                cached.1
            );

            let scores = self.topology.peer_scores().read().await;
            let score = scores.get(&cached.0).map(|s| s.total_score).unwrap_or(0.5);

            return Ok(RouteQueryResult {
                query_id: String::new(),
                upstream_id: upstream_id.to_string(),
                providers: vec![ProviderInfo {
                    node_id: cached.0,
                    upstream_url: String::new(),
                    waf_policy: None,
                    hops: cached.1,
                    ttl: Duration::from_secs(300),
                    score,
                    priority_tier: 0,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: None,
                }],
                discovered_at: Instant::now(),
            });
        }

        if !self.topology.can_forward_service(upstream_id) {
            return Err(MeshTransportError::ServiceNotAllowed(
                upstream_id.to_string(),
            ));
        }

        let query_id = format!("{}-{}", self.config.node_id(), uuid::Uuid::new_v4());
        let collection_timeout = Duration::from_millis(self.config.routing.query_timeout_ms);

        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();

        self.pending_queries
            .lock()
            .await
            .register(query_id.clone(), response_tx);

        let peer_query_count = self.config.routing.peer_query_count.min(3);
        let known_peers = self
            .topology
            .get_best_peers_for_query(upstream_id, peer_query_count)
            .await;

        if !known_peers.is_empty() {
            tracing::debug!(
                "Sending parallel stream route queries to {} peers for upstream {}",
                known_peers.len(),
                upstream_id
            );

            let queries: Vec<_> = known_peers
                .iter()
                .map(|peer_id| {
                    let peer_id = peer_id.clone();
                    let query_id = query_id.clone();
                    let upstream_id = upstream_id.to_string();
                    let transport = self.clone();
                    async move {
                        transport
                            .send_route_query_stream(&peer_id, &query_id, &upstream_id)
                            .await
                    }
                })
                .collect();

            join_all(queries).await;

            tokio::time::sleep(collection_timeout).await;

            let providers = {
                let mut pending = self.pending_queries.lock().await;
                pending
                    .collected_providers
                    .remove(&query_id)
                    .unwrap_or_default()
            };

            self.pending_queries.lock().await.pending.remove(&query_id);

            if !providers.is_empty() {
                let scores = self.topology.peer_scores().read().await;
                let mut providers_with_scores: Vec<ProviderInfo> = providers
                    .into_iter()
                    .map(|mut p| {
                        if p.score == 0.5 {
                            p.score = scores.get(&p.node_id).map(|s| s.total_score).unwrap_or(0.5);
                        }
                        p
                    })
                    .collect();

                providers_with_scores.sort_by(|a, b| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });

                let _best = providers_with_scores.first().cloned();

                return Ok(RouteQueryResult {
                    query_id,
                    upstream_id: upstream_id.to_string(),
                    providers: providers_with_scores,
                    discovered_at: Instant::now(),
                });
            }
        }

        // Fallback to global node if local peers didn't have providers
        if let Some(global_id) = self.topology.get_closest_global_node().await {
            tracing::debug!(
                "Querying global node {} for upstream {}",
                global_id,
                upstream_id
            );

            // Re-register for the global node query
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_queries
                .lock()
                .await
                .register(query_id.clone(), tx);

            // Use stream for reliable delivery to global node
            if self
                .send_route_query_stream(&global_id, &query_id, upstream_id)
                .await
                .is_ok()
            {
                // Wait for response via oneshot or fallback to cache polling
                let global_result = tokio::select! {
                    result = rx => {
                        match result {
                            Ok(r) => Some(r),
                            Err(_) => self.wait_for_route_event(upstream_id, collection_timeout).await,
                        }
                    }
                    _ = tokio::time::sleep(collection_timeout) => {
                        self.wait_for_route_event(upstream_id, Duration::ZERO).await
                    }
                };
                self.pending_queries.lock().await.take(&query_id);
                if let Some(r) = global_result {
                    return Ok(r);
                }
            } else {
                self.pending_queries.lock().await.take(&query_id);
            }
        }

        // Check for local upstream as last resort
        if let Some(local) = self.topology.get_upstream_info(upstream_id).await {
            if local.is_local {
                return Ok(RouteQueryResult {
                    query_id: String::new(),
                    upstream_id: upstream_id.to_string(),
                    providers: vec![ProviderInfo {
                        node_id: self.topology.node_id().to_string(),
                        upstream_url: local.upstream_url,
                        waf_policy: local.waf_policy,
                        hops: 0,
                        ttl: Duration::from_secs(300),
                        score: 1.0,
                        priority_tier: local.priority_tier,
                        tier_claim: None,
                        org_id: None,
                        mesh_name: self.config.mesh_name().map(String::from),
                    }],
                    discovered_at: Instant::now(),
                });
            }
        }

        Err(MeshTransportError::NoRouteToUpstream(
            upstream_id.to_string(),
        ))
    }

    /// Preflight: query a newly connected peer for their known routes to warm our cache
    /// Proactive cache warming: periodically query for popular routes from peers
    /// This keeps the route cache warm without waiting for actual requests
    ///
    /// Periodic DHT cache resync for edge nodes
    /// Checks if local cache is stale and requests fresh snapshot from global nodes
    pub async fn announce_upstream(
        &self,
        upstream_id: &str,
        action: crate::mesh::protocol::AnnounceAction,
    ) -> Result<(), MeshTransportError> {
        if !self.topology.can_forward_service(upstream_id) {
            tracing::debug!(
                "Not announcing upstream {} - service not allowed by policy",
                upstream_id
            );
            return Ok(());
        }

        match action {
            crate::mesh::protocol::AnnounceAction::Add
            | crate::mesh::protocol::AnnounceAction::Update => {
                self.topology
                    .add_local_upstream(
                        upstream_id.to_string(),
                        self.config
                            .local_upstreams
                            .get(upstream_id)
                            .map(|u| u.upstream_url.clone())
                            .unwrap_or_default(),
                        self.config
                            .local_upstreams
                            .get(upstream_id)
                            .and_then(|u| u.geo.clone()),
                    )
                    .await;
            }
            crate::mesh::protocol::AnnounceAction::Remove => {
                self.topology.remove_local_upstream(upstream_id).await;
            }
        }

        for entry in self.peer_connections.iter() {
            let peer = entry.value();
            if peer.role.is_global() {
                let upstream_id_for_sig = upstream_id.to_string();
                let upstream_id_for_msg = upstream_id.to_string();

                let signature = if let Some(ref signer) = self.mesh_signer {
                    let content = format!("{}:{:?}", upstream_id_for_sig, action);
                    signer.sign(content.as_bytes())
                } else {
                    Vec::new()
                };

                let (origin_signature, origin_ed25519_pubkey) =
                    if let Some(ref signer) = self.origin_ed25519_signer {
                        let content = format!(
                            "{}:{:?}:{}",
                            upstream_id_for_sig,
                            action,
                            self.config.node_id()
                        );
                        (
                            signer.sign(&content).into_bytes(),
                            signer.verifying_key().into(),
                        )
                    } else {
                        (Vec::new(), String::new().into())
                    };

                let announce_message = MeshMessage::UpstreamAnnounce {
                    upstream_id: upstream_id_for_msg.into(),
                    action,
                    signature,
                    origin_ed25519_pubkey,
                    origin_signature,
                };

                let encoded = match announce_message.encode() {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to encode announce message for {}: {:?}",
                            peer.node_id,
                            e
                        );
                        continue;
                    }
                };

                if let Err(e) = peer.connection.send_datagram(encoded.into()) {
                    tracing::warn!(
                        "Failed to announce upstream {} to global node {}: {}",
                        upstream_id,
                        peer.node_id,
                        e
                    );
                } else {
                    tracing::debug!(
                        "Announced upstream {} to global node {}",
                        upstream_id,
                        peer.node_id
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn broadcast_upstream_block(
        &self,
        upstream_id: &str,
        reason: &str,
        blocked_duration_secs: u64,
    ) {
        if !self.config.ratelimit_block_advertisement {
            tracing::debug!("Upstream block advertisement disabled in config");
            return;
        }

        // Validate: don't broadcast blocks with 0 or very small duration
        if blocked_duration_secs < 1 {
            tracing::warn!(
                "Refusing to broadcast block with zero or negative duration: {}",
                blocked_duration_secs
            );
            return;
        }

        let blocked_until = Instant::now() + Duration::from_secs(blocked_duration_secs);
        let mesh_identifier = self.config.router_id();

        let parts: Vec<&str> = upstream_id.split('.').collect();
        let (mesh_id, service_id) = if parts.len() >= 2 {
            (parts[0].to_string(), parts[1..].join("."))
        } else {
            (mesh_identifier.to_string(), upstream_id.to_string())
        };

        self.topology
            .block_upstream(
                mesh_id.as_str(),
                service_id.as_str(),
                blocked_until,
                reason,
                self.config.node_id().as_str(),
            )
            .await;

        // Send Unix timestamp for when block expires (not remaining duration)
        let block_until_unix = crate::utils::safe_unix_timestamp() + blocked_duration_secs;

        let block_message = MeshMessage::UpstreamBlocked {
            mesh_identifier: mesh_id.into(),
            service_id: service_id.into(),
            blocked_until: block_until_unix,
            reason: reason.into(),
            origin_node_id: self.config.node_id().into(),
        };

        let (success_count, fail_count) = self
            .broadcast_to_random_peers(
                block_message,
                0.5,
                Some(crate::mesh::config::MeshNodeRole::GLOBAL),
            )
            .await;

        tracing::info!(
            upstream_id,
            reason,
            blocked_duration_secs,
            "Fanout broadcast upstream block: {} to {} global nodes ({} failed)",
            upstream_id,
            success_count,
            fail_count
        );
    }

    pub async fn broadcast_peer_block(
        &self,
        node_id: &str,
        reason: &str,
        blocked_duration_secs: u64,
        evidence: Option<crate::mesh::dht::AuditReceipt>,
    ) {
        let block_until_unix = crate::utils::safe_unix_timestamp() + blocked_duration_secs;

        let block_message = MeshMessage::PeerBlocked {
            node_id: node_id.into(),
            blocked_until: block_until_unix,
            reason: reason.into(),
            blocked_by: self.config.node_id().into(),
            evidence_receipt: evidence,
        };

        let (success_count, fail_count) = self
            .broadcast_to_random_peers(
                block_message,
                0.5,
                Some(crate::mesh::config::MeshNodeRole::GLOBAL),
            )
            .await;

        tracing::info!(
            node_id,
            reason,
            blocked_duration_secs,
            "Fanout broadcast peer block: {} to {} global nodes ({} failed)",
            node_id,
            success_count,
            fail_count
        );
    }

    pub async fn broadcast_to_random_peers(
        &self,
        message: MeshMessage,
        fanout_factor: f64,
        role_filter: Option<crate::mesh::config::MeshNodeRole>,
    ) -> (usize, usize) {
        let peer_count = self.topology.get_healthy_peer_count().await;

        if peer_count == 0 {
            return (0, 0);
        }

        let fanout_count = ((peer_count as f64) * fanout_factor).ceil() as usize;
        let target_count = fanout_count.max(1).min(peer_count);

        let mut peers = self.topology.get_random_peers(target_count, None).await;

        if let Some(role) = role_filter {
            peers.retain(|p| p.role == role);
        }

        if peers.is_empty() {
            return (0, 0);
        }

        let mut success_count = 0;
        let mut fail_count = 0;

        let mut futures = FuturesUnordered::new();
        for peer in &peers {
            let transport = self.clone();
            let message = message.clone();
            let node_id = peer.node_id.clone();
            futures.push(async move {
                let result = transport.send_datagram_to_peer(&node_id, &message).await;
                (node_id, result)
            });
        }
        while let Some((node_id, result)) = futures.next().await {
            match result {
                Ok(_) => success_count += 1,
                Err(e) => {
                    fail_count += 1;
                    tracing::debug!("Fanout broadcast to {} failed: {}", node_id, e);
                }
            }
        }

        tracing::debug!(
            "Fanout broadcast: {} peers selected, {} sent (mesh: {}, factor: {:.2})",
            peers.len(),
            success_count,
            peer_count,
            fanout_factor
        );

        (success_count, fail_count)
    }

    pub async fn broadcast_to_all_peers(
        &self,
        message: MeshMessage,
        role_filter: Option<crate::mesh::config::MeshNodeRole>,
    ) -> (usize, usize, Vec<String>) {
        let peer_count = self.topology.get_healthy_peer_count().await;

        if peer_count == 0 {
            return (0, 0, Vec::new());
        }

        let mut peers = self.topology.get_all_connected_peers().await;

        if let Some(role) = role_filter {
            peers.retain(|p| p.role == role);
        }

        if peers.is_empty() {
            return (0, 0, Vec::new());
        }

        let mut success_count = 0;
        let mut fail_count = 0;
        let sent_node_ids: Vec<String> = peers.iter().map(|p| p.node_id.clone()).collect();

        let mut futures = FuturesUnordered::new();
        for peer in &peers {
            let transport = self.clone();
            let message = message.clone();
            let node_id = peer.node_id.clone();
            futures.push(async move {
                let result = transport.send_datagram_to_peer(&node_id, &message).await;
                (node_id, result)
            });
        }
        while let Some((node_id, result)) = futures.next().await {
            match result {
                Ok(_) => success_count += 1,
                Err(e) => {
                    fail_count += 1;
                    tracing::debug!("Broadcast to all peers {} failed: {}", node_id, e);
                }
            }
        }

        tracing::debug!(
            "Broadcast to all peers: {} peers selected, {} sent, {} failed (mesh: {})",
            peers.len(),
            success_count,
            fail_count,
            peer_count
        );

        (success_count, fail_count, sent_node_ids)
    }

    pub fn connected_peer_count(&self) -> usize {
        self.peer_connections.len()
    }

    pub fn get_connected_peers(&self) -> Vec<String> {
        self.peer_connections
            .iter()
            .map(|e| e.value().node_id.clone())
            .collect()
    }

    pub async fn proxy_http_request<B>(
        &self,
        peer_id: &str,
        _target_url: &str,
        request: Request<B>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshTransportError>
    where
        B: HttpBody + Send,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        use http_body_util::BodyExt;

        let peer = match self.peer_connections.get(peer_id) {
            Some(p) => p,
            None => {
                if let Some(peer_state) = self.topology.get_peer(peer_id).await {
                    tracing::debug!(
                        "Peer {} not connected, attempting on-demand connection to {}",
                        peer_id,
                        peer_state.address
                    );
                    let peer_config = MeshPeerConfig {
                        address: peer_state.address.clone(),
                        auth_token: None,
                    };
                    if self.connect_to_peer(&peer_config).await.is_ok() {
                        tracing::info!(
                            "On-demand connection established to peer {} at {}",
                            peer_id,
                            peer_state.address
                        );
                    }
                }
                self.peer_connections
                    .get(peer_id)
                    .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?
            }
        };

        let (mut send_stream, mut recv_stream) = {
            let mut pool = peer.stream_pool.lock().await;
            pool.acquire().await
        }
        .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let method = request.method().to_string();
        let uri = request.uri().to_string();
        let headers = request.headers();

        let mut header_str = format!("{} {} HTTP/1.1\r\n", method, uri);
        for (name, value) in headers.iter() {
            header_str.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
        }
        header_str.push_str("\r\n");

        send_stream
            .write_all(header_str.as_bytes())
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let body = request
            .collect()
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?
            .to_bytes();
        if !body.is_empty() {
            send_stream
                .write_all(&body)
                .await
                .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        }

        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
        let mut reader = BufReader::with_capacity(4096, &mut recv_stream);

        let mut response_headers = String::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;

        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .await
                .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if trimmed.to_lowercase().starts_with("content-length:") {
                content_length = Some(
                    trimmed
                        .split(':')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .parse()
                        .unwrap_or(0),
                );
            }
            if trimmed.to_lowercase().starts_with("transfer-encoding:")
                && trimmed.to_lowercase().contains("chunked")
            {
                chunked = true;
            }
            response_headers.push_str(trimmed);
            response_headers.push_str("\r\n");
        }
        response_headers.push_str("\r\n");

        let status_line = response_headers
            .lines()
            .next()
            .unwrap_or("HTTP/1.1 500 Internal Server Error");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("500")
            .parse::<u16>()
            .unwrap_or(500);

        let mut response_builder = hyper::Response::builder().status(status_code);

        for line in response_headers.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                response_builder = response_builder.header(name.trim(), value.trim());
            }
        }

        let _body_bytes = if chunked {
            let mut body = Vec::new();
            loop {
                let mut size_line = String::new();
                reader
                    .read_line(&mut size_line)
                    .await
                    .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    break;
                }
                if body.len().saturating_add(size) > MAX_HTTP_BODY_SIZE {
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Chunked body too large: exceeds {} bytes",
                        MAX_HTTP_BODY_SIZE
                    )));
                }
                let mut chunk = vec![0u8; size];
                reader
                    .read_exact(&mut chunk)
                    .await
                    .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
                body.extend_from_slice(&chunk);
                let mut crlf = [0u8; 2];
                reader
                    .read_exact(&mut crlf)
                    .await
                    .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
            }
            body
        } else if let Some(len) = content_length {
            if len > MAX_HTTP_BODY_SIZE {
                return Err(MeshTransportError::ReceiveFailed(format!(
                    "Content-Length too large: {} bytes (max {})",
                    len, MAX_HTTP_BODY_SIZE
                )));
            }
            let mut body = vec![0u8; len];
            reader
                .read_exact(&mut body)
                .await
                .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
            body
        } else {
            let mut body = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                if body.len() >= MAX_HTTP_BODY_SIZE {
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Response body too large: exceeds {} bytes",
                        MAX_HTTP_BODY_SIZE
                    )));
                }
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if body.len().saturating_add(n) > MAX_HTTP_BODY_SIZE {
                            return Err(MeshTransportError::ReceiveFailed(format!(
                                "Response body too large: exceeds {} bytes",
                                MAX_HTTP_BODY_SIZE
                            )));
                        }
                        body.extend_from_slice(&buf[..n]);
                    }
                    Err(_) => break,
                }
            }
            body
        };

        let body = body;
        let full_body = http_body_util::Full::new(body);
        let boxed_body: BoxBody<Bytes, Infallible> = full_body.boxed();
        let response = response_builder
            .body(boxed_body)
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        {
            let mut pool = peer.stream_pool.lock().await;
            pool.release((send_stream, recv_stream));
        }

        Ok(response)
    }

    fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(CONNECTION_RATE_LIMIT_WINDOW_SECS);

        let mut times = self.connection_times.write();
        times.retain(|t| now.duration_since(*t) < window);

        if times.len() >= self.config.connection.max_pending_connections {
            tracing::warn!(
                "Connection rate limit exceeded: {} connections in {}s",
                times.len(),
                CONNECTION_RATE_LIMIT_WINDOW_SECS
            );
            return false;
        }

        times.push(now);
        true
    }

    pub fn is_global_node(&self) -> bool {
        self.config.role.is_global()
    }

    pub fn get_node_mesh_id(&self) -> Option<String> {
        self.config
            .origin_signing_key
            .as_ref()
            .map(|k| k.mesh_id.clone())
    }

    pub fn get_node_id(&self) -> String {
        self.config.node_id()
    }

    pub fn get_global_verifying_key(&self) -> String {
        self.config.global_node_key.clone().unwrap_or_default()
    }

    pub fn get_origin_signer(&self) -> Option<Arc<crate::integrity::Ed25519Signer>> {
        self.origin_ed25519_signer.clone()
    }

    pub fn get_mesh_config(&self) -> Arc<MeshConfig> {
        self.config.clone()
    }

    pub(crate) async fn complete_dht_query(&self, request_id: &str, record: DhtRecord) -> bool {
        let mut pending = self.pending_dht_queries.lock().await;
        if let Some(sender) = pending.remove(request_id) {
            return sender.send(record).is_ok();
        }
        false
    }

    pub(crate) async fn get_pending_consistent_read_responses(
        &self,
    ) -> Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<MeshMessage>>>> {
        self.pending_consistent_read_responses.clone()
    }

    #[allow(dead_code)]
    pub(crate) async fn get_pending_snapshot_responses(
        &self,
    ) -> Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>> {
        self.pending_snapshot_responses.clone()
    }
}

impl crate::mesh::dht::routing::manager::FindNodeTransport for MeshTransport {
    fn send_find_node(
        &self,
        target: crate::mesh::dht::routing::node_id::NodeId,
        request_id: String,
    ) {
        let this = self.clone();
        let node_id = self.config.node_id();
        tokio::spawn(async move {
            let find_node = MeshMessage::FindNode {
                request_id: request_id.into(),
                target_node_id: target.as_bytes().to_vec(),
                requester_node_id: node_id.into(),
                timestamp: crate::utils::safe_unix_timestamp(),
            };
            let _ = this
                .send_datagram_to_peer(&target.to_string(), &find_node)
                .await;
        });
    }
}

impl crate::mesh::dht::routing::manager::PingTransport for MeshTransport {
    fn send_ping(&self, node_id: &str, request_id: String, local_node_id: String) {
        let this = self.clone();
        let node_id_owned = node_id.to_string();
        let _node_id = node_id;
        tokio::spawn(async move {
            let ping = MeshMessage::Ping {
                request_id: request_id.into(),
                node_id: local_node_id.into(),
                timestamp: crate::utils::safe_unix_timestamp(),
            };
            let _ = this.send_datagram_to_peer(&node_id_owned, &ping).await;
        });
    }
}
