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

use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};

#[allow(unused_imports)]
use crate::lifecycle::{
    remaining, AuxiliaryRegistryEntry, AuxiliaryTask, AuxiliaryTaskExit, AuxiliaryTaskKind,
    DhtPeerMutation, DhtPeerSnapshot, FailedStartupResidue, MeshAcceptLoopReport,
    MeshLifecycleState, MeshShutdownReport, MeshStartupPolicy, MeshStartupReport, MeshStartupStage,
    MeshTaskExit, MeshTaskExitReason, MeshTaskId, MeshTaskIdGenerator, PeerSessionStopOutcome,
    PeerSessionTask, RecoveryReport, RollbackReport, StagedPeerResource, StagedTopologySnapshot,
};
use crate::task_group::MeshTaskGroup;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::cert::MeshCertManager;
use crate::config::{MeshConfig, MeshPeerConfig, MeshTlsMode};
use crate::dht::DEFAULT_GET_BY_PREFIX_LIMIT;
use crate::kem::MlKem768;
use crate::organization::{MemberCertificate, OrgPublicKey};
use crate::protocol::{
    DhtRecord, MeshMessage, MeshPeerInfo, ProviderInfo, RouteQueryResult, UpstreamInfo,
    MESH_MESSAGE_VERSION,
};
use crate::session::SessionManager;
use crate::topology::{MeshTopology, PeerStatus};
use crate::transport_types::MeshStreamPool;
use synvoid_tunnel::quic::runtime::QuicRuntime;

pub use crate::transports::MeshTransportManager;

pub use crate::transport_core::{
    get_time_validation_error_count, validate_system_time, MeshTransportError,
    MAX_REASONABLE_TIMESTAMP, MIN_REASONABLE_TIMESTAMP,
};

pub use crate::transport_types::{MeshGlobalRateLimiter, MeshPeerConnection};

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

pub(crate) struct AuxiliarySubmissionTestHooks {
    pub after_lock: Option<std::sync::Arc<tokio::sync::Barrier>>,
    pub before_insert: Option<std::sync::Arc<tokio::sync::Barrier>>,
    pub before_gate_release: Option<std::sync::Arc<tokio::sync::Barrier>>,
}

impl Default for AuxiliarySubmissionTestHooks {
    fn default() -> Self {
        Self {
            after_lock: None,
            before_insert: None,
            before_gate_release: None,
        }
    }
}

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
    pub(crate) pending_serverless_invocations:
        Arc<Mutex<HashMap<String, oneshot::Sender<crate::protocol::ServerlessInvokeResponse>>>>,
    pub(crate) pending_consistent_read_responses:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<crate::protocol::MeshMessage>>>>,
    pub(crate) pending_snapshot_responses:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    pub(crate) pending_snapshot_transfers: Arc<Mutex<HashMap<String, InProgressSnapshot>>>,
    pub(crate) auth_failures: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub(crate) peer_message_times: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub(crate) snapshot_request_times: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub(crate) global_rate_limiter: Arc<MeshGlobalRateLimiter>,
    pub(crate) org_manager: Arc<RwLock<crate::organization::OrganizationManager>>,
    pub(crate) org_key_manager: Arc<crate::org_key_manager::OrgKeyManager>,
    pub(crate) tier_key_store: Option<Arc<RwLock<crate::dht::TierKeyStore>>>,
    pub(crate) tier_key_encryption: Option<Arc<crate::tier_key_encryption::TierKeyEncryption>>,
    pub(crate) origin_ed25519_signer: Option<Arc<synvoid_integrity::Ed25519Signer>>,
    pub(crate) mesh_signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
    pub(crate) record_store: Option<Arc<crate::dht::RecordStoreManager>>,
    pub(crate) routing_manager: Option<Arc<crate::dht::routing::DhtRoutingManager>>,
    pub(crate) threat_intel: Option<Arc<crate::threat_intel::ThreatIntelligenceManager>>,
    pub(crate) yara_rules: Option<Arc<crate::yara_rules::YaraRulesManager>>,
    pub(crate) seen_messages: Arc<RwLock<lru_time_cache::LruCache<String, Instant>>>,
    pub(crate) stake_manager: Option<Arc<crate::dht::StakeManager>>,
    pub(crate) mlkem_session_manager: Option<Arc<SessionManager<MlKem768>>>,
    pub(crate) backend_pool: Option<Arc<crate::backend::MeshBackendPool>>,
    #[cfg(feature = "dns")]
    pub(crate) dns_resolver: Option<Arc<dyn synvoid_dns::resolver::DnsResolver>>,
    #[cfg(feature = "dns")]
    pub(crate) dns_registry: Option<Arc<synvoid_dns::MeshDnsRegistry>>,
    #[cfg(feature = "dns")]
    pub(crate) dns_zones: Arc<RwLock<Option<Arc<synvoid_dns::server::ShardedZoneStore>>>>,
    #[allow(clippy::type_complexity)]
    pub(crate) site_config_sync_tx: Arc<
        RwLock<
            Option<
                mpsc::Sender<(
                    String,
                    String,
                    Option<crate::protocol::ProxyCachePreferences>,
                )>,
            >,
        >,
    >,
    pub(crate) verification_manager:
        Arc<RwLock<Option<Arc<crate::verification::VerificationTaskManager>>>>,
    pub(crate) revocation_list: Option<Arc<crate::peer_auth::GlobalNodeRevocationList>>,
    pub(crate) serverless_manager:
        Arc<RwLock<Option<Arc<synvoid_serverless::manager::ServerlessManager>>>>,
    #[cfg(feature = "dns")]
    pub(crate) ownership_challenge_store: Arc<RwLock<OwnershipChallengeStore>>,
    pub(crate) raft_instance: Arc<RwLock<Option<Arc<crate::raft::instance::RaftInstance>>>>,
    pub(crate) pending_membership_changes: Arc<tokio::sync::Mutex<Vec<PendingMembershipChange>>>,
    pub(crate) edge_replica_manager:
        Arc<RwLock<Option<Arc<crate::raft::edge_replica::EdgeReplicaManager>>>>,
    pub(crate) raft_proposal_replay_cache:
        Arc<tokio::sync::Mutex<crate::raft::state_machine::ReplayProtectionCache>>,
    pub(crate) task_group: Arc<tokio::sync::Mutex<MeshTaskGroup>>,
    pub(crate) lifecycle_state: Arc<tokio::sync::Mutex<MeshLifecycleState>>,
    pub(crate) shutdown_started: Arc<AtomicBool>,
    pub(crate) mesh_exit_tx: broadcast::Sender<MeshTaskExit>,
    pub(crate) peer_sessions:
        Arc<tokio::sync::Mutex<HashMap<String, crate::lifecycle::PeerSessionTask>>>,
    pub(crate) startup_failure_hook:
        Arc<Mutex<Option<Box<dyn Fn(StartupFailurePoint) -> Result<(), String> + Send>>>>,
    /// Serializes lifecycle start/stop transitions to prevent interleaving.
    pub(crate) lifecycle_op: tokio::sync::Mutex<()>,
    /// Globally unique task ID generator shared across task-group generations.
    pub(crate) id_generator: Arc<MeshTaskIdGenerator>,
    /// Atomic projection of `Running` lifecycle state for synchronous checks.
    pub(crate) running_projection: Arc<AtomicBool>,
    /// Report from the mesh accept loop, populated during shutdown.
    pub(crate) accept_loop_report: Arc<tokio::sync::Mutex<MeshAcceptLoopReport>>,
    /// Retained metadata from an incomplete startup rollback (Iteration 73, Phase 8).
    pub(crate) failed_startup_residue: Arc<tokio::sync::Mutex<Option<FailedStartupResidue>>>,
    /// Auxiliary (preflight/best-effort) tasks owned by the transport (Iteration 73, Phase 13-14).
    pub(crate) auxiliary_tasks:
        Arc<tokio::sync::Mutex<HashMap<MeshTaskId, AuxiliaryRegistryEntry>>>,
    /// Serializes auxiliary task deduplication, capacity, reservation, and insertion (Iteration 80).
    pub(crate) auxiliary_submission_lock: Arc<tokio::sync::Mutex<()>>,
    /// Channel for peer session exit events, consumed by the session reaper (Iteration 73, Phase 15-18).
    pub(crate) session_exit_tx: broadcast::Sender<crate::lifecycle::PeerSessionExit>,
    /// Generation counter incremented at each startup, used to validate accept-loop report freshness (Phase 19).
    pub(crate) startup_generation: Arc<AtomicU64>,
    /// Per-session generation counter for incoming connections (accept-loop path).
    /// Outbound sessions use the stage counter; inbound sessions use this atomic.
    pub(crate) session_generation: Arc<AtomicU64>,
    /// Shutdown signal for the session reaper (Iteration 74, Phase 14).
    pub(crate) session_reaper_shutdown: Arc<watch::Sender<bool>>,
    /// Channel for auxiliary task exit events, consumed by the auxiliary reaper (Iteration 74, Phase 20).
    pub(crate) auxiliary_exit_tx: broadcast::Sender<crate::lifecycle::AuxiliaryTaskExit>,
    /// Aggregate stream handler drain counters (Phase 23). Incremented in
    /// `peer_message_loop` after each session's drain, read during shutdown.
    pub(crate) aggregate_handler_drained: Arc<AtomicUsize>,
    pub(crate) aggregate_handler_aborted: Arc<AtomicUsize>,
    pub(crate) aggregate_handler_failed: Arc<AtomicUsize>,
    pub(crate) auxiliary_test_hooks: Arc<Mutex<Option<AuxiliarySubmissionTestHooks>>>,
}

/// Failure injection points for deterministic startup testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupFailurePoint {
    /// After critical tasks (mesh_maintenance, datagram_listener) are spawned.
    AfterCriticalTasks,
    /// During seed bootstrap phase.
    DuringSeedBootstrap,
    /// During configured peer connection phase.
    DuringPeerConnect,
    /// Before any peer connection (seed or configured) is attempted (after DHT init).
    /// Replaces BeforePeerConnect which fired before DHT initialization.
    AfterDhtInitialization,
    /// During DHT bootstrap phase.
    DuringDhtBootstrap,
    /// During QUIC runtime server start.
    DuringRuntimeStart,
    /// Before lifecycle state transitions to Running (post-staging, pre-commit).
    BeforeLifecycleCommit,
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
            task_group: self.task_group.clone(),
            lifecycle_state: self.lifecycle_state.clone(),
            shutdown_started: self.shutdown_started.clone(),
            mesh_exit_tx: self.mesh_exit_tx.clone(),
            peer_sessions: self.peer_sessions.clone(),
            startup_failure_hook: self.startup_failure_hook.clone(),
            lifecycle_op: tokio::sync::Mutex::new(()),
            id_generator: self.id_generator.clone(),
            running_projection: self.running_projection.clone(),
            accept_loop_report: self.accept_loop_report.clone(),
            failed_startup_residue: self.failed_startup_residue.clone(),
            auxiliary_tasks: self.auxiliary_tasks.clone(),
            auxiliary_submission_lock: self.auxiliary_submission_lock.clone(),
            startup_generation: self.startup_generation.clone(),
            session_generation: self.session_generation.clone(),
            session_exit_tx: self.session_exit_tx.clone(),
            session_reaper_shutdown: self.session_reaper_shutdown.clone(),
            auxiliary_exit_tx: self.auxiliary_exit_tx.clone(),
            aggregate_handler_drained: self.aggregate_handler_drained.clone(),
            aggregate_handler_aborted: self.aggregate_handler_aborted.clone(),
            aggregate_handler_failed: self.aggregate_handler_failed.clone(),
            auxiliary_test_hooks: self.auxiliary_test_hooks.clone(),
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

fn mesh_tls_mode_requires_peer_cert_identity(mode: MeshTlsMode) -> bool {
    matches!(mode, MeshTlsMode::Strict | MeshTlsMode::Tofu)
}

fn mesh_tls_mode_label(mode: MeshTlsMode) -> &'static str {
    match mode {
        MeshTlsMode::Strict => "strict",
        MeshTlsMode::Tofu => "tofu",
        MeshTlsMode::Permissive => "permissive",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerIdentityState {
    Missing,
    NotCertificateDer,
    CertificateDer,
}

fn validate_peer_identity_state_for_mode(
    mode: MeshTlsMode,
    peer_identity_state: PeerIdentityState,
    peer_node_id: &str,
) -> Result<(), MeshTransportError> {
    let requires_identity = mesh_tls_mode_requires_peer_cert_identity(mode);
    match peer_identity_state {
        PeerIdentityState::Missing if requires_identity => {
            Err(MeshTransportError::AuthFailed(format!(
                "Peer {} has no TLS peer identity; mesh TLS mode requires certificate identity ({})",
                peer_node_id,
                mesh_tls_mode_label(mode)
            )))
        }
        PeerIdentityState::NotCertificateDer if requires_identity => {
            Err(MeshTransportError::AuthFailed(format!(
                "Peer {} TLS identity is not CertificateDer; mesh TLS mode requires certificate identity ({})",
                peer_node_id,
                mesh_tls_mode_label(mode)
            )))
        }
        _ => Ok(()),
    }
}

impl MeshTransport {
    fn verify_peer_connection_certificate_if_available(
        &self,
        peer_node_id: &str,
        connection: &quinn::Connection,
    ) -> Result<(), MeshTransportError> {
        let cert_mgr = self.cert_manager.read();
        let tls_mode = cert_mgr.tls_mode();
        let Some(peer_identity) = connection.peer_identity() else {
            validate_peer_identity_state_for_mode(
                tls_mode,
                PeerIdentityState::Missing,
                peer_node_id,
            )?;
            tracing::warn!(
                "Peer {} has no TLS peer identity exposed by QUIC connection; skipping certificate verification hook",
                peer_node_id
            );
            return Ok(());
        };

        let Some(peer_cert) = peer_identity.downcast_ref::<rustls_pki_types::CertificateDer<'_>>()
        else {
            validate_peer_identity_state_for_mode(
                tls_mode,
                PeerIdentityState::NotCertificateDer,
                peer_node_id,
            )?;
            tracing::warn!(
                "Peer {} TLS identity is not a rustls CertificateDer; skipping certificate verification hook",
                peer_node_id
            );
            return Ok(());
        };
        validate_peer_identity_state_for_mode(
            tls_mode,
            PeerIdentityState::CertificateDer,
            peer_node_id,
        )?;

        match cert_mgr.verify_peer_certificate_identity_binding(
            peer_node_id,
            peer_cert.as_ref(),
            None,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(MeshTransportError::AuthFailed(format!(
                "Peer {} certificate verification or identity binding failed",
                peer_node_id
            ))),
            Err(e) => Err(MeshTransportError::AuthFailed(format!(
                "Peer {} certificate verification error: {}",
                peer_node_id, e
            ))),
        }
    }

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
        record_store: Option<Arc<crate::dht::RecordStoreManager>>,
        _routing_manager: Option<Arc<crate::dht::routing::DhtRoutingManager>>,
        threat_intel: Option<Arc<crate::threat_intel::ThreatIntelligenceManager>>,
        mesh_signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
        stake_manager: Option<Arc<crate::dht::StakeManager>>,
        backend_pool: Option<Arc<crate::backend::MeshBackendPool>>,
        #[cfg(feature = "dns")] dns_resolver: Option<Arc<dyn synvoid_dns::resolver::DnsResolver>>,
        #[cfg(feature = "dns")] dns_registry: Option<Arc<synvoid_dns::MeshDnsRegistry>>,
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
                .map(|pk| Arc::new(synvoid_integrity::Ed25519Signer::new(pk)))
        });

        let seen_messages =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 10000);

        let tier_key_store = if config.role.contains(crate::config::MeshNodeRole::GLOBAL) {
            Some(Arc::new(RwLock::new(crate::dht::TierKeyStore::new())))
        } else {
            None
        };

        let mlkem_session_manager = if let Some(ref mlkem_config) = config.mlkem {
            if mlkem_config.enabled {
                let session_config: crate::session::SessionConfig = mlkem_config.clone().into();
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
                const HKDF_INFO: &[u8] = b"synvoid-tier-key-root";
                let hk = Hkdf::<Sha256>::new(None, signing_key);
                let mut okm = [0u8; 32];
                if hk.expand(HKDF_INFO, &mut okm).is_ok() {
                    tracing::info!("TierKey DHT encryption enabled for global node");
                    Some(Arc::new(
                        crate::tier_key_encryption::TierKeyEncryption::new(okm.to_vec()),
                    ))
                } else {
                    tracing::warn!("Failed to derive tier key encryption root key");
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
                let mut org_mgr = crate::organization::OrganizationManager::new();
                if is_genesis {
                    org_mgr.init_genesis_org();
                    tracing::info!(
                        "Initialized genesis node - genesis and admin organizations created"
                    );
                }
                Arc::new(RwLock::new(org_mgr))
            },
            org_key_manager: {
                let mgr = crate::org_key_manager::OrgKeyManager::new(
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
                Some(Arc::new(crate::peer_auth::GlobalNodeRevocationList::new()))
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
                crate::raft::state_machine::ReplayProtectionCache::default(),
            )),
            task_group: Arc::new(tokio::sync::Mutex::new(MeshTaskGroup::new())),
            lifecycle_state: Arc::new(tokio::sync::Mutex::new(MeshLifecycleState::Stopped)),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            mesh_exit_tx: {
                let (tx, _) = broadcast::channel(64);
                tx
            },
            peer_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            startup_failure_hook: Arc::new(Mutex::new(None)),
            lifecycle_op: tokio::sync::Mutex::new(()),
            id_generator: Arc::new(MeshTaskIdGenerator::new()),
            running_projection: Arc::new(AtomicBool::new(false)),
            accept_loop_report: Arc::new(tokio::sync::Mutex::new(MeshAcceptLoopReport::default())),
            failed_startup_residue: Arc::new(tokio::sync::Mutex::new(None)),
            auxiliary_tasks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            auxiliary_submission_lock: Arc::new(tokio::sync::Mutex::new(())),
            session_exit_tx: {
                let (tx, _) = broadcast::channel(64);
                tx
            },
            startup_generation: Arc::new(AtomicU64::new(0)),
            session_generation: Arc::new(AtomicU64::new(0)),
            session_reaper_shutdown: {
                let (tx, _) = watch::channel(false);
                Arc::new(tx)
            },
            auxiliary_exit_tx: {
                let (tx, _) = broadcast::channel(64);
                tx
            },
            aggregate_handler_drained: Arc::new(AtomicUsize::new(0)),
            aggregate_handler_aborted: Arc::new(AtomicUsize::new(0)),
            aggregate_handler_failed: Arc::new(AtomicUsize::new(0)),
            auxiliary_test_hooks: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_edge_replica_manager(
        &self,
        manager: Arc<crate::raft::edge_replica::EdgeReplicaManager>,
    ) {
        *self.edge_replica_manager.write() = Some(manager);
    }

    pub fn get_edge_replica_manager(
        &self,
    ) -> Option<Arc<crate::raft::edge_replica::EdgeReplicaManager>> {
        self.edge_replica_manager.read().clone()
    }

    /// Set a failure injection hook for startup testing.
    pub fn set_startup_failure_hook(
        &self,
        hook: impl Fn(StartupFailurePoint) -> Result<(), String> + Send + 'static,
    ) {
        *self.startup_failure_hook.blocking_lock() = Some(Box::new(hook));
    }

    /// Clear the startup failure hook.
    pub fn clear_startup_failure_hook(&self) {
        *self.startup_failure_hook.blocking_lock() = None;
    }

    /// Check if a startup failure hook is currently set.
    pub fn has_startup_failure_hook(&self) -> bool {
        self.startup_failure_hook.blocking_lock().is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_auxiliary_test_hooks(&self, hooks: AuxiliarySubmissionTestHooks) {
        *self.auxiliary_test_hooks.blocking_lock() = Some(hooks);
    }

    #[cfg(test)]
    pub(crate) fn clear_auxiliary_test_hooks(&self) {
        *self.auxiliary_test_hooks.blocking_lock() = None;
    }

    pub fn set_site_config_sync_callback(
        &self,
        tx: mpsc::Sender<(
            String,
            String,
            Option<crate::protocol::ProxyCachePreferences>,
        )>,
    ) {
        let mut lock = self.site_config_sync_tx.write();
        *lock = Some(tx);
    }

    #[cfg(feature = "dns")]
    pub fn set_dns_zones(&self, zones: Arc<synvoid_dns::server::ShardedZoneStore>) {
        let mut lock = self.dns_zones.write();
        *lock = Some(zones);
    }

    pub fn set_verification_manager(
        &self,
        manager: Arc<crate::verification::VerificationTaskManager>,
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

    pub fn get_org_manager(&self) -> Arc<RwLock<crate::organization::OrganizationManager>> {
        self.org_manager.clone()
    }

    pub fn get_record_store(&self) -> Option<Arc<crate::dht::RecordStoreManager>> {
        self.record_store.clone()
    }

    pub fn get_routing_manager(&self) -> Option<Arc<crate::dht::routing::DhtRoutingManager>> {
        self.routing_manager.clone()
    }

    pub fn get_org_key_manager(&self) -> Arc<crate::org_key_manager::OrgKeyManager> {
        self.org_key_manager.clone()
    }

    pub fn set_routing_manager(&mut self, manager: Arc<crate::dht::routing::DhtRoutingManager>) {
        self.routing_manager = Some(manager);
    }

    pub fn get_tier_key_store(&self) -> Option<Arc<RwLock<crate::dht::TierKeyStore>>> {
        self.tier_key_store.clone()
    }

    pub fn set_tier_key_encryption(
        &mut self,
        enc: Arc<crate::tier_key_encryption::TierKeyEncryption>,
    ) {
        self.tier_key_encryption = Some(enc);
    }

    pub fn get_tier_key_encryption(
        &self,
    ) -> Option<Arc<crate::tier_key_encryption::TierKeyEncryption>> {
        self.tier_key_encryption.clone()
    }

    pub fn get_topology(&self) -> Arc<MeshTopology> {
        self.topology.clone()
    }

    pub fn get_threat_intel(&self) -> Option<Arc<crate::threat_intel::ThreatIntelligenceManager>> {
        self.threat_intel.clone()
    }

    pub fn get_stake_manager(&self) -> Option<Arc<crate::dht::StakeManager>> {
        self.stake_manager.clone()
    }

    pub fn get_mlkem_session_manager(&self) -> Option<Arc<SessionManager<MlKem768>>> {
        self.mlkem_session_manager.clone()
    }

    pub fn set_mlkem_session_manager(&mut self, manager: Arc<SessionManager<MlKem768>>) {
        self.mlkem_session_manager = Some(manager);
    }

    pub fn set_raft_instance(&self, instance: Arc<crate::raft::instance::RaftInstance>) {
        *self.raft_instance.write() = Some(instance);
    }

    pub fn get_raft_instance(
        &self,
    ) -> Arc<RwLock<Option<Arc<crate::raft::instance::RaftInstance>>>> {
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
            authorized_at: synvoid_utils::safe_unix_timestamp(),
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
                let key = crate::dht::keys::DhtKey::node_capability(node_id, capability);
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
    ) -> Vec<crate::protocol::ServerlessFunctionAnnounce> {
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

                functions.push(crate::protocol::ServerlessFunctionAnnounce {
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
            let key = crate::dht::keys::DhtKey::serverless_function(&func_name);
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
    ) -> Option<crate::dht::CapabilityAttestation> {
        if !self.config.role.is_global() {
            tracing::warn!("Only global nodes can attest capabilities");
            return None;
        }

        let peer_state = if node_id == self.config.node_id() {
            Some(crate::topology::PeerState {
                node_id: node_id.to_string(),
                address: String::new(),
                role: self.config.role,
                status: crate::topology::PeerStatus::Healthy,
                capabilities: crate::protocol::MeshCapabilities {
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
                first_seen: synvoid_utils::current_timestamp(),
                last_seen: synvoid_utils::current_timestamp(),
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
        let timestamp = synvoid_utils::current_timestamp();
        let global_node_id = self.config.node_id();

        let temp_attestation = crate::dht::CapabilityAttestation::new(
            node_id.to_string(),
            capability.to_string(),
            global_node_id.clone(),
            String::new(),
            vec![],
            timestamp,
        );

        let signature = signer.sign(temp_attestation.signable_content().as_bytes());

        let signer_public_key = signer.get_public_key();

        let attestation = crate::dht::CapabilityAttestation::new(
            node_id.to_string(),
            capability.to_string(),
            global_node_id,
            signer_public_key,
            signature,
            timestamp,
        );

        if let Some(ref record_store) = self.record_store {
            let key = crate::dht::keys::DhtKey::capability_attestation(node_id, capability);
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
        peer_state: &crate::topology::PeerState,
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
    ) -> Option<crate::dht::CapabilityAttestation> {
        let key = crate::dht::keys::DhtKey::capability_attestation(node_id, capability);
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
        attestation: &crate::dht::CapabilityAttestation,
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
        site_config: &synvoid_config::site::SiteConfig,
    ) {
        let Some(ref record_store) = self.record_store else {
            tracing::warn!("Cannot publish transform config: no record store");
            return;
        };

        let image_rights_config = &site_config.image_rights;
        let static_config = &site_config.r#static;

        let image_protection_json = serde_json::json!({
            "enabled": image_rights_config.enabled,
            "min_size_bytes": image_rights_config.max_dimension.map(|v| v as u64),
            "whitelist_patterns": image_rights_config.whitelist_patterns,
        });
        let image_protection_key = format!("upstream_image_protection:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&image_protection_json) {
            record_store.store_and_announce(image_protection_key, bytes, 3600);
        }

        let site_image_rights_json = serde_json::json!({
            "enabled": image_rights_config.enabled,
            "level": image_rights_config.level,
            "intensity": image_rights_config.intensity,
            "seed": image_rights_config.seed,
            "max_dimension": image_rights_config.max_dimension,
            "jpeg_quality": image_rights_config.jpeg_quality,
            "edge_only": image_rights_config.edge_only,
        });
        let site_image_rights_key = format!("site_image_rights_config:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&site_image_rights_json) {
            record_store.store_and_announce(site_image_rights_key, bytes, 3600);
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
            let proxy_cache_prefs = crate::protocol::ProxyCachePreferences::from(cache_config);
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

        if transport_arc.backend_pool.is_some() {
            let raft_client = Arc::new(crate::raft::client::RaftAwareClient::new(
                transport_arc.clone(),
                transport_arc.config.clone(),
                transport_arc.record_store.clone().map(|r| {
                    let r: std::sync::Arc<dyn crate::raft::consensus::RecordReader> = r;
                    r
                }),
            ));

            if let Some(ref manager) = *transport_arc.edge_replica_manager.read() {
                let rc = raft_client.clone();
                let m = manager.clone();
                // Phase 24: One-shot initialization — sets the edge replica
                // manager on the raft client. Completes immediately; if it
                // fails, the edge replica manager is simply not wired and
                // subsequent raft operations log the absence. No lifecycle
                // ownership needed.
                tokio::spawn(async move {
                    rc.set_edge_replica_manager(m).await;
                });
            }

            transport_arc
                .org_key_manager
                .set_raft_client(raft_client.clone());

            raft_client.start_reconciliation_loop();
        }

        let wasm_dist_manager = Arc::new(crate::wasm_dist::WasmDistManager::new());
        crate::wasm_dist::set_global_wasm_dist_manager(wasm_dist_manager);
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
        manager: Arc<synvoid_serverless::manager::ServerlessManager>,
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
        proxy_cache_preferences: Option<crate::protocol::ProxyCachePreferences>,
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
    ) -> Result<crate::protocol::ServerlessInvokeResponse, MeshTransportError> {
        let request = crate::protocol::ServerlessInvokeRequest::new(
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
        match synvoid_utils::get_first_non_loopback_ip() {
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

        let timestamp = synvoid_utils::safe_unix_timestamp();

        let key_exchange_endpoint = self.get_key_exchange_endpoint();

        // Include endpoint in signable message
        let endpoint_str = key_exchange_endpoint.clone().unwrap_or_default();
        let signable = format!(
            "{}:{}:{}:{}:{}",
            self.config.node_id(),
            self.config.global_node_key.as_deref().unwrap_or(""),
            crate::protocol::GlobalNodeAction::UpdateKeyExchange as u8,
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
        let msg = crate::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: self.config.node_id().into(),
            public_key: self
                .config
                .global_node_key
                .clone()
                .unwrap_or_default()
                .into(),
            action: crate::protocol::GlobalNodeAction::UpdateKeyExchange,
            timestamp,
            signature,
            key_exchange_endpoint: key_exchange_endpoint.map(|s| s.into()),
            cert_chain: None,
        };

        let _ = self
            .broadcast_to_random_peers(msg, 0.5, Some(crate::config::MeshNodeRole::GLOBAL))
            .await;
        tracing::info!(
            "Updated key exchange endpoint for global node {}",
            self.config.node_id()
        );
    }

    pub(crate) async fn handle_ping(&self, from_peer: &str, request_id: &str) {
        tracing::debug!("Received Ping from {}", from_peer);

        let response = crate::protocol::MeshMessage::Pong {
            request_id: request_id.into(),
            node_id: self.config.node_id().into(),
            timestamp: crate::protocol::MeshMessage::generate_timestamp(),
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

    pub async fn start(&self) -> Result<(), MeshTransportError> {
        self.start_with_policy(MeshStartupPolicy::default())
            .await
            .map(|_| ())
    }

    /// Start the mesh transport with an explicit startup policy.
    ///
    /// This is the primary startup entry point. The policy controls whether
    /// bootstrap failures (seeds, peers, DHT) are fatal or produce a degraded
    /// startup report. Every failure after the first task spawn flows through
    /// the rollback funnel, guaranteeing no orphaned tasks survive a failed attempt.
    pub async fn start_with_policy(
        &self,
        policy: MeshStartupPolicy,
    ) -> Result<MeshStartupReport, MeshTransportError> {
        let _lifecycle_guard = self.lifecycle_op.lock().await;

        // Phase 1: Acquire lifecycle lock and validate state
        {
            let mut state = self.lifecycle_state.lock().await;
            if !state.can_start() {
                return Err(MeshTransportError::LifecycleConflict(format!(
                    "Cannot start: current state is {state}"
                )));
            }
            state.transition_to_starting().map_err(|e| {
                MeshTransportError::StartupFailed(format!("State transition failed: {e}"))
            })?;
        }

        // Phase 2: Create staged startup
        let mut stage = MeshStartupStage::new(MeshTaskGroup::new_with_forward_and_id_gen(
            self.mesh_exit_tx.clone(),
            self.id_generator.clone(),
        ));
        let shutdown_rx = stage.task_group.shutdown_receiver();
        self.shutdown_started.store(false, Ordering::SeqCst);

        // Reset accept loop report for this startup generation
        {
            let mut report = self.accept_loop_report.lock().await;
            let gen = self.startup_generation.fetch_add(1, Ordering::SeqCst) + 1;
            report.generation = gen;
            report.drained_handshakes = 0;
            report.aborted_handshakes = 0;
            report.rejected_at_capacity = 0;
        }

        // Phase 3-10: Run all startup phases, routing ALL failures through rollback
        let report = match self
            .run_startup_phases(&mut stage, &policy, &shutdown_rx)
            .await
        {
            Ok(report) => report,
            Err(error) => return self.rollback_and_return(&mut stage, error).await,
        };

        match self.commit_startup(&mut stage, report).await {
            Ok(report) => Ok(report),
            Err(error) => self.rollback_and_return(&mut stage, error).await,
        }
    }

    /// Check and invoke the startup failure hook at the given point.
    /// Returns `Err` if the hook triggers a failure.
    async fn check_startup_failure_hook(
        &self,
        point: StartupFailurePoint,
    ) -> Result<(), MeshTransportError> {
        let hook = self.startup_failure_hook.lock().await;
        if let Some(ref f) = *hook {
            f(point).map_err(|e| MeshTransportError::StartupFailed(e))
        } else {
            Ok(())
        }
    }

    /// Run all startup phases after the first task has been spawned.
    ///
    /// Every failure here must flow through the rollback funnel — no post-spawn
    /// `?` may directly leave this method without rollback.
    async fn run_startup_phases(
        &self,
        stage: &mut MeshStartupStage,
        policy: &MeshStartupPolicy,
        shutdown_rx: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<MeshStartupReport, MeshTransportError> {
        let mut report = MeshStartupReport::default();

        // Phase 3: Start critical transport loops
        let config = self.config.clone();
        let topology = self.topology.clone();
        let peer_connections = self.peer_connections.clone();
        let maintenance_shutdown = shutdown_rx.clone();
        stage
            .task_group
            .spawn_critical("mesh_maintenance", async move {
                Self::mesh_maintenance_loop(
                    config,
                    topology,
                    peer_connections,
                    maintenance_shutdown,
                )
                .await;
            });

        let peer_connections_dg = self.peer_connections.clone();
        let datagram_shutdown = shutdown_rx.clone();
        stage
            .task_group
            .spawn_critical("datagram_listener", async move {
                Self::datagram_listener_loop(peer_connections_dg, datagram_shutdown).await;
            });

        self.check_startup_failure_hook(StartupFailurePoint::AfterCriticalTasks)
            .await?;

        // Phase 3.5: Initialize or restore DHT routing table BEFORE any peer
        // connection. The routing table must exist before any seed or configured
        // peer connection callback can mutate it via dht_on_peer_connected()
        // (Iteration 88, Part A — Phase 1).
        let mut dht_ready = false;
        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                let was_initialized = rm.is_initialized().await;
                if !was_initialized {
                    rm.init().await;
                }
                let initialized = rm.is_initialized().await;
                report.dht_routing_initialized = initialized;
                stage.record_dht_init(crate::lifecycle::DhtInitializationSnapshot {
                    was_initialized_this_attempt: !was_initialized && initialized,
                });
                if !initialized {
                    let reason = "DHT routing initialization did not create a routing table";
                    if policy.require_dht_initialization {
                        return Err(MeshTransportError::StartupFailed(reason.into()));
                    }
                    report.degraded_reasons.push(reason.into());
                } else if !was_initialized {
                    tracing::info!("DHT routing table initialized during startup");
                } else {
                    tracing::debug!("DHT routing table already initialized, skipping");
                }
                dht_ready = initialized;
            }
        }

        // Phase 3.75: Hook fires after DHT initialization but BEFORE any peer
        // connection. This proves the "initialized-before-connect" invariant
        // (Iteration 88, Part E).
        self.check_startup_failure_hook(StartupFailurePoint::AfterDhtInitialization)
            .await?;

        // Phase 4: Bootstrap from seeds
        self.check_startup_failure_hook(StartupFailurePoint::DuringSeedBootstrap)
            .await?;
        if !self.config.seeds.is_empty() {
            match self.bootstrap_from_seeds(stage).await {
                Ok(()) => {
                    report.connected_seed_count = self.config.seeds.len();
                }
                Err(e) => {
                    if policy.require_seed_connectivity {
                        return Err(MeshTransportError::StartupFailed(format!(
                            "Seed bootstrap required but failed: {e}"
                        )));
                    }
                    report
                        .degraded_reasons
                        .push(format!("Seed bootstrap failed: {e}"));
                }
            }
        }

        // Phase 5: Connect configured peers
        self.check_startup_failure_hook(StartupFailurePoint::DuringPeerConnect)
            .await?;
        if !self.config.peers.is_empty() {
            match self.connect_to_peers(stage).await {
                Ok(()) => {
                    report.connected_configured_peer_count = self.config.peers.len();
                }
                Err(e) => {
                    if policy.require_configured_peers {
                        return Err(MeshTransportError::StartupFailed(format!(
                            "Configured peer connection required but failed: {e}"
                        )));
                    }
                    report
                        .degraded_reasons
                        .push(format!("Peer connection failed: {e}"));
                }
            }
        }

        // Phase 6: DHT bootstrap — only if routing table was initialized.
        self.check_startup_failure_hook(StartupFailurePoint::DuringDhtBootstrap)
            .await?;
        if dht_ready {
            if let Some(ref rm) = self.routing_manager {
                match self.dht_bootstrap_from_seeds(rm.clone()).await {
                    Ok(()) => {
                        report.dht_bootstrapped = true;
                    }
                    Err(e) => {
                        if policy.require_dht_bootstrap {
                            return Err(MeshTransportError::StartupFailed(format!(
                                "DHT bootstrap required but failed: {e}"
                            )));
                        }
                        report
                            .degraded_reasons
                            .push(format!("DHT bootstrap failed: {e}"));
                    }
                }
            }
        }

        // Phase 7: Start periodic background loops
        // Register topology and DHT routing maintenance tasks under the task group.
        {
            let topo_shutdown = shutdown_rx.clone();
            let topo_specs = self.topology.build_background_tasks(topo_shutdown);
            stage.task_group.register_background_specs(topo_specs);
        }
        if dht_ready {
            if let Some(ref rm) = self.routing_manager {
                let dht_shutdown = shutdown_rx.clone();
                let dht_specs = rm.build_background_tasks(dht_shutdown);
                stage.task_group.register_background_specs(dht_specs);
            }
        } else if self.routing_manager.is_some() {
            tracing::warn!("DHT routing unavailable; skipping DHT maintenance tasks");
        }

        let connection_config = self.config.connection.clone();
        let transport_for_maintenance = Arc::new(self.clone_for_maintenance());

        if connection_config.min_peer_connections > 0 {
            let maintenance_transport = transport_for_maintenance.clone();
            let maintenance_interval = Duration::from_secs(30);
            let mut bg_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("connection_maintenance", async move {
                    let mut interval = tokio::time::interval(maintenance_interval);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                maintenance_transport.maintain_connections().await;
                                maintenance_transport.perform_auto_slash().await;
                            }
                            _ = bg_shutdown.changed() => {
                                if *bg_shutdown.borrow() { break; }
                            }
                        }
                    }
                });

            let health_transport = transport_for_maintenance.clone();
            let health_interval = Duration::from_secs(connection_config.health_check_interval_secs);
            let mut health_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("peer_health_check", async move {
                    let mut interval = tokio::time::interval(health_interval);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                let peers: Vec<String> = health_transport
                                    .peer_connections
                                    .iter()
                                    .map(|e| e.value().node_id.clone())
                                    .collect();
                                for peer_id in peers {
                                    health_transport.perform_health_check(&peer_id).await;
                                }
                            }
                            _ = health_shutdown.changed() => {
                                if *health_shutdown.borrow() { break; }
                            }
                        }
                    }
                });

            let cache_warm_transport = transport_for_maintenance.clone();
            let cache_warm_interval = Duration::from_secs(60);
            let mut cache_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("cache_warming", async move {
                    let mut interval = tokio::time::interval(cache_warm_interval);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                cache_warm_transport.proactive_cache_warm().await;
                            }
                            _ = cache_shutdown.changed() => {
                                if *cache_shutdown.borrow() { break; }
                            }
                        }
                    }
                });

            let dht_resync_transport = transport_for_maintenance.clone();
            let mut dht_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("dht_cache_resync", async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(30));
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                dht_resync_transport.dht_cache_resync().await;
                            }
                            _ = dht_shutdown.changed() => {
                                if *dht_shutdown.borrow() { break; }
                            }
                        }
                    }
                });

            let load_report_transport = transport_for_maintenance.clone();
            let load_report_interval = Duration::from_secs(60);
            let mut load_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("load_reporter", async move {
                    let mut interval = tokio::time::interval(load_report_interval);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                load_report_transport.send_load_report_to_peers().await;
                            }
                            _ = load_shutdown.changed() => {
                                if *load_shutdown.borrow() { break; }
                            }
                        }
                    }
                });

            let heartbeat_transport = transport_for_maintenance.clone();
            let heartbeat_interval = Duration::from_secs(30);
            let mut heartbeat_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("global_node_heartbeat", async move {
                    let mut interval = tokio::time::interval(heartbeat_interval);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                heartbeat_transport.publish_global_node_heartbeat().await;
                            }
                            _ = heartbeat_shutdown.changed() => {
                                if *heartbeat_shutdown.borrow() { break; }
                            }
                        }
                    }
                });
        }

        // Phase 8: Role-specific tasks
        if self.config.role.is_global() {
            let transport_for_attest = Arc::new(self.clone_for_maintenance());
            let mut attest_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_background("global_self_attestation", async move {
                    let node_id = transport_for_attest.config.node_id().to_string();
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {
                            transport_for_attest.attest_capability(&node_id, "waf").await;
                            transport_for_attest.attest_capability(&node_id, "threat_intel").await;
                            transport_for_attest.attest_capability(&node_id, "dns").await;
                            tracing::info!("Global node '{}' self-attested capabilities", node_id);
                        }
                        _ = attest_shutdown.changed() => {}
                    }
                });
        }

        if self.config.role.is_edge() {
            let pow_config = self.config.clone();
            let mut pow_shutdown = shutdown_rx.clone();
            stage.task_group.spawn_background("pow_nonce_refresh", async move {
                let refresh_interval = Duration::from_secs(2700);
                let mut interval = tokio::time::interval(refresh_interval);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            tracing::debug!("Refreshing PoW nonce cache");
                            if let Some(ref pk_hex) = pow_config.signing_public_key() {
                                use base64::Engine;
                                if let Ok(pk_bytes) =
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_hex)
                                {
                                    if let Some(nonce) =
                                        crate::dht::routing::node_id::NodeId::find_pow_nonce(&pk_bytes)
                                    {
                                        pow_config.set_cached_pow_nonce(nonce);
                                        tracing::info!("Refreshed PoW nonce: {}", nonce);
                                    } else {
                                        tracing::warn!("Failed to compute new PoW nonce during refresh");
                                    }
                                }
                            }
                        }
                        _ = pow_shutdown.changed() => {
                            if *pow_shutdown.borrow() { break; }
                        }
                    }
                }
            });
        }

        if let Some(ref mlkem_manager) = self.mlkem_session_manager {
            let mlkem_manager = mlkem_manager.clone();
            let rotation_interval = mlkem_manager.config().rotation_interval;
            let session_rotation_transport = Arc::new(self.clone_for_maintenance());
            let mut kem_shutdown = shutdown_rx.clone();
            stage.task_group.spawn_background("mlkem_key_rotation", async move {
                let mut interval = tokio::time::interval(rotation_interval);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
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
                                            timestamp: synvoid_utils::current_timestamp(),
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
                        _ = kem_shutdown.changed() => {
                            if *kem_shutdown.borrow() { break; }
                        }
                    }
                }
            });
        }

        // Phase 9: Start QUIC accept loop
        self.check_startup_failure_hook(StartupFailurePoint::DuringRuntimeStart)
            .await?;
        if let Some(ref runtime) = self.runtime {
            let incoming = runtime
                .start_server()
                .await
                .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;
            let transport = Arc::new(self.clone_for_maintenance());
            let accept_shutdown = shutdown_rx.clone();
            stage
                .task_group
                .spawn_critical("mesh_accept_loop", async move {
                    Self::mesh_accept_loop(transport, incoming, accept_shutdown).await;
                });
            stage.mark_runtime_started();
        }

        Ok(report)
    }

    /// Commit a successful startup: transfer staged resources to the transport
    /// and transition lifecycle to `Running`.
    ///
    /// Commit order is race-safe:
    /// 1. Validate lifecycle state is Starting (without mutating yet)
    /// 2. Pre-commit failure injection (test only)
    /// 3. Prepare compatibility shutdown sender
    /// 4. Transfer staged task group into transport ownership
    /// 5. Store staged runtime/listener handles (if any)
    /// 6. Transition lifecycle state to Running
    /// 7. Set running projection
    /// 8. Mark stage committed
    ///
    /// If any step after task-group transfer fails, the task group is
    /// restored to the stage so the caller can roll back.
    async fn commit_startup(
        &self,
        stage: &mut MeshStartupStage,
        report: MeshStartupReport,
    ) -> Result<MeshStartupReport, MeshTransportError> {
        // 1. Validate lifecycle state is Starting (without mutating yet)
        {
            let state = self.lifecycle_state.lock().await;
            if !matches!(*state, MeshLifecycleState::Starting) {
                return Err(MeshTransportError::StartupFailed(format!(
                    "Commit attempted but lifecycle is {state}, expected Starting"
                )));
            }
        }

        // 2. Pre-commit failure injection
        self.check_startup_failure_hook(StartupFailurePoint::BeforeLifecycleCommit)
            .await?;

        // 3. Prepare compatibility shutdown sender
        {
            let (compat_tx, _) = broadcast::channel(1);
            let _ = compat_tx.send(());
            *self.shutdown_tx.write() = Some(compat_tx);
        }

        // 4. Transfer staged task group into transport ownership
        let old_task_group = {
            let mut tg = self.task_group.lock().await;
            let (c, b, ch) = tg.active_count();
            if c + b + ch > 0 {
                return Err(MeshTransportError::LifecycleConflict(format!(
                    "cannot commit startup over non-empty task group: {c} critical, {b} background, {ch} children"
                )));
            }
            std::mem::replace(&mut *tg, std::mem::take(&mut stage.task_group))
        };
        // old_task_group is dropped here (its tasks were already forwarded via exit_tx)

        // 5. Store staged runtime/listener handles (if any)
        // (runtime_started is tracked in the stage; the actual QUIC endpoint
        //  is already bound by the accept loop task)

        // 6. Transition lifecycle state to Running
        {
            let mut state = self.lifecycle_state.lock().await;
            match state.transition_to_running() {
                Ok(()) => {}
                Err(e) => {
                    // Lifecycle transition failed — restore task group so caller can roll back
                    let mut tg = self.task_group.lock().await;
                    stage.task_group = std::mem::replace(&mut *tg, old_task_group);
                    return Err(MeshTransportError::StartupFailed(format!(
                        "State transition to running failed: {e}"
                    )));
                }
            }
        }

        // 7. Set running projection
        self.running_projection.store(true, Ordering::SeqCst);

        // 8. Mark stage committed
        self.shutdown_started.store(false, Ordering::SeqCst);
        stage.committed = true;

        // 9. Spawn session reaper on the committed task group (Iteration 73, Phase 15-18)
        self.spawn_session_reaper().await;
        // 10. Spawn auxiliary task reaper (Iteration 74, Phase 21)
        self.spawn_auxiliary_reaper().await;

        tracing::info!(
            "Mesh transport started (lifecycle: running, degraded={})",
            !report.degraded_reasons.is_empty()
        );
        Ok(report)
    }

    /// Spawn the session reaper task that watches for peer session completions
    /// and removes entries from the peer_sessions registry (Iteration 73, Phase 15-18).
    ///
    /// The reaper is spawned as a critical background task on the transport's task group.
    /// It uses generation counters to prevent stale completions from removing newer entries.
    ///
    /// The reaper is cancellation-aware: it selects on both the exit receiver and a
    /// shutdown signal, ensuring it exits cleanly during shutdown (Iteration 74, Phase 14).
    /// Removed handles are awaited outside the lock to avoid holding it during join
    /// (Iteration 74, Phase 15).
    async fn spawn_session_reaper(&self) {
        let transport = self.clone();
        let mut exit_rx = self.session_exit_tx.subscribe();
        let mut shutdown_rx = self.session_reaper_shutdown.subscribe();

        let mut group = self.task_group.lock().await;
        group.spawn_critical("session_reaper", async move {
            loop {
                tokio::select! {
                    event = exit_rx.recv() => {
                        match event {
                            Ok(exit) => {
                                let removed = {
                                    let mut sessions = transport.peer_sessions.lock().await;
                                    match sessions.get(&exit.session_id) {
                                        Some(task) if task.generation == exit.generation => {
                                            sessions.remove(&exit.session_id)
                                        }
                                        Some(task) => {
                                            tracing::debug!(
                                                "Session reaper skipped stale entry for {} (exit gen={}, registry gen={})",
                                                exit.session_id,
                                                exit.generation,
                                                task.generation
                                            );
                                            None
                                        }
                                        None => None,
                                    }
                                };
                                // Await the handle outside the lock (Iteration 74, Phase 15)
                                if let Some(task) = removed {
                                    match task.handle.await {
                                        Ok(()) => {
                                            tracing::debug!(
                                                "Session reaper joined handle for {} ({:?})",
                                                exit.session_id,
                                                exit.reason
                                            );
                                        }
                                        Err(error) if error.is_panic() => {
                                            tracing::warn!(
                                                "Session reaper: wrapper task for {} panicked after sending exit event",
                                                exit.session_id
                                            );
                                        }
                                        Err(error) => {
                                            tracing::debug!(
                                                "Session reaper: wrapper task for {} cancelled after sending exit event: {}",
                                                exit.session_id,
                                                error
                                            );
                                        }
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Session reaper lagged by {} events, scanning for finished sessions", n);
                                transport.reap_finished_peer_sessions().await;
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::debug!("Session reaper received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Scan peer_sessions for completed handles and remove them (Iteration 74, Phase 17).
    ///
    /// This handles the case where the broadcast reaper lagged and missed exit events.
    /// Finished handles are joined outside the lock to avoid holding it during await.
    async fn reap_finished_peer_sessions(&self) {
        let mut to_join = Vec::new();
        {
            let mut sessions = self.peer_sessions.lock().await;
            let mut to_remove = Vec::new();
            for (session_id, task) in sessions.iter() {
                if task.handle.is_finished() {
                    to_remove.push(session_id.clone());
                }
            }
            for session_id in to_remove {
                if let Some(task) = sessions.remove(&session_id) {
                    to_join.push(task);
                }
            }
        }
        // Join all finished handles outside the lock
        for task in to_join {
            match task.handle.await {
                Ok(()) => {
                    tracing::debug!(
                        "Reaper lag recovery: joined finished session handle for {}",
                        task.session_id
                    );
                }
                Err(error) if error.is_panic() => {
                    tracing::warn!(
                        "Reaper lag recovery: finished session handle for {} panicked",
                        task.session_id
                    );
                }
                Err(error) => {
                    tracing::debug!(
                        "Reaper lag recovery: finished session handle for {} cancelled: {}",
                        task.session_id,
                        error
                    );
                }
            }
        }
    }

    /// Spawn an auxiliary task with deduplication, capacity gating, and
    /// proper exit publication (Iteration 80).
    ///
    /// Uses a gated-start pattern: the future is spawned but waits for a
    /// oneshot signal before executing. The ownership record is inserted
    /// before the gate is opened, ensuring completion cannot race ahead
    /// of registration.
    ///
    /// Serialized by `auxiliary_submission_lock` so that deduplication,
    /// capacity checking, state validation, stale-task teardown, and
    /// insertion are atomic. Lifecycle state is rechecked under the lock
    /// to prevent submissions after shutdown/recovery intent begins.
    ///
    /// # Lock ordering
    ///
    /// Submission acquires locks in this order (never reversed):
    /// ```text
    /// auxiliary_submission_lock
    ///   -> lifecycle_state lock
    ///   -> auxiliary_tasks lock
    /// ```
    ///
    /// Shutdown/recovery acquires:
    /// ```text
    /// lifecycle operation lock (lifecycle_op)
    ///   -> auxiliary_submission_lock
    ///     -> auxiliary_tasks lock
    /// ```
    pub(crate) async fn spawn_auxiliary_task<F>(
        &self,
        kind: AuxiliaryTaskKind,
        name: &'static str,
        session_id: Option<String>,
        dedup_key: Option<String>,
        future: F,
    ) -> Result<MeshTaskId, crate::lifecycle::SpawnAuxiliaryError>
    where
        F: std::future::Future<Output = MeshTaskExitReason> + Send + 'static,
    {
        let task_id = self.id_generator.next();

        // Acquire submission lock — serializes all state/dedup/capacity/insert operations.
        let _guard = self.auxiliary_submission_lock.lock().await;

        #[cfg(test)]
        if let Some(ref hooks) = *self.auxiliary_test_hooks.lock().await {
            if let Some(ref barrier) = hooks.after_lock {
                barrier.wait().await;
            }
        }

        // Recheck lifecycle state under the lock (Phase 19).
        {
            let state = self.lifecycle_state.lock().await;
            let transport_state = match *state {
                crate::lifecycle::MeshLifecycleState::Stopped => {
                    crate::lifecycle::MeshTransportState::Stopped
                }
                crate::lifecycle::MeshLifecycleState::Starting => {
                    crate::lifecycle::MeshTransportState::Starting
                }
                crate::lifecycle::MeshLifecycleState::Running => {
                    crate::lifecycle::MeshTransportState::Running
                }
                crate::lifecycle::MeshLifecycleState::Stopping => {
                    crate::lifecycle::MeshTransportState::Stopping
                }
                crate::lifecycle::MeshLifecycleState::Failed => {
                    crate::lifecycle::MeshTransportState::Failed
                }
            };
            if !crate::lifecycle::auxiliary_submission_allowed(transport_state, kind) {
                tracing::debug!(
                    "Auxiliary submission rejected: lifecycle state {:?} does not allow {:?}",
                    transport_state,
                    kind
                );
                metrics::counter!("mesh_auxiliary_capacity_dropped").increment(1);
                return Err(crate::lifecycle::SpawnAuxiliaryError::LifecycleNotRunning(
                    transport_state,
                ));
            }
        }

        // Deduplication and capacity check.
        const MAX_CONCURRENT_EDGE_REPLICA_REFRESH: usize = 8;
        let stale_tasks = {
            let mut aux = self.auxiliary_tasks.lock().await;
            match Self::dedup_and_check_capacity(
                &mut aux,
                kind,
                &dedup_key,
                MAX_CONCURRENT_EDGE_REPLICA_REFRESH,
            ) {
                Ok(stale) => {
                    if !stale.is_empty() {
                        metrics::counter!("mesh_auxiliary_deduplicated")
                            .increment(stale.len() as u64);
                    }
                    stale
                }
                Err(()) => {
                    metrics::counter!("mesh_auxiliary_capacity_dropped").increment(1);
                    return Err(crate::lifecycle::SpawnAuxiliaryError::CapacityExceeded);
                }
            }
        };

        // Abort and await stale tasks (still under submission lock — volume is low).
        for old_task in stale_tasks {
            old_task.handle.abort();
            let _ = old_task.handle.await;
            tracing::debug!("Aborted stale auxiliary task {} (dedup)", old_task.task_id);
        }

        metrics::counter!("mesh_auxiliary_submitted").increment(1);

        // Gate: future cannot start until registration is complete.
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let aux_exit_tx = self.auxiliary_exit_tx.clone();
        let task_id_for_exit = task_id;
        let session_id_for_exit = session_id.clone();

        let handle = tokio::spawn(async move {
            // Wait for registration to complete before executing user future.
            if start_rx.await.is_err() {
                // Gate dropped (submission rejected after spawn).
                let reason = MeshTaskExitReason::Cancelled;
                let _ = aux_exit_tx.send(AuxiliaryTaskExit {
                    task_id: task_id_for_exit,
                    session_id: session_id_for_exit,
                    reason: reason.clone(),
                });
                return MeshTaskExit {
                    id: task_id_for_exit,
                    name,
                    class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                    reason,
                };
            }
            let reason = future.await;
            match &reason {
                MeshTaskExitReason::CleanCompletion => {
                    metrics::counter!("mesh_auxiliary_succeeded").increment(1);
                }
                MeshTaskExitReason::Error(_) => {
                    metrics::counter!("mesh_auxiliary_failed").increment(1);
                }
                _ => {
                    metrics::counter!("mesh_auxiliary_failed").increment(1);
                }
            }
            let _ = aux_exit_tx.send(AuxiliaryTaskExit {
                task_id: task_id_for_exit,
                session_id: session_id_for_exit,
                reason: reason.clone(),
            });
            MeshTaskExit {
                id: task_id_for_exit,
                name,
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason,
            }
        });

        #[cfg(test)]
        if let Some(ref hooks) = *self.auxiliary_test_hooks.lock().await {
            if let Some(ref barrier) = hooks.before_insert {
                barrier.wait().await;
            }
        }

        // Insert into registry BEFORE opening the gate.
        {
            let mut aux = self.auxiliary_tasks.lock().await;
            aux.insert(
                task_id,
                AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                    task_id,
                    session_id,
                    kind,
                    handle,
                    dedup_key,
                }),
            );
        }

        #[cfg(test)]
        if let Some(ref hooks) = *self.auxiliary_test_hooks.lock().await {
            if let Some(ref barrier) = hooks.before_gate_release {
                barrier.wait().await;
            }
        }

        // Signal the gate — future can now execute.
        let _ = start_tx.send(());

        Ok(task_id)
    }

    /// Apply deduplication and capacity checks to the auxiliary task registry.
    ///
    /// Returns `Ok(stale_tasks_removed)` on success (caller should insert the
    /// new task). Returns `Err(())` when capacity is exhausted (caller should
    /// abort the new handle).
    ///
    /// Stale tasks matching `dedup_key` are removed from the map. The caller
    /// is responsible for aborting and awaiting the returned handles outside
    /// the registry lock.
    pub(crate) fn dedup_and_check_capacity(
        aux: &mut std::collections::HashMap<MeshTaskId, AuxiliaryRegistryEntry>,
        kind: AuxiliaryTaskKind,
        dedup_key: &Option<String>,
        capacity: usize,
    ) -> Result<Vec<AuxiliaryTask>, ()> {
        // Deduplication: remove stale tasks matching the dedup key.
        let mut stale = Vec::new();
        if let Some(ref dk) = dedup_key {
            let stale_ids: Vec<_> = aux
                .iter()
                .filter(|(_id, entry)| entry.dedup_key().as_deref() == Some(dk.as_str()))
                .map(|(id, _)| *id)
                .collect();
            for id in stale_ids {
                if let Some(entry) = aux.remove(&id) {
                    if let AuxiliaryRegistryEntry::Running(task) = entry {
                        stale.push(task);
                    }
                }
            }
        }

        // Capacity check: count active tasks of the matching kind.
        let active = aux.values().filter(|e| e.kind() == kind).count();
        if active >= capacity {
            return Err(());
        }

        Ok(stale)
    }

    /// Spawn the auxiliary task reaper that watches for completed auxiliary tasks
    /// and removes them from the auxiliary_tasks registry (Iteration 74, Phase 21).
    ///
    /// The reaper is cancellation-aware and handles broadcast lag gracefully.
    async fn spawn_auxiliary_reaper(&self) {
        let transport = self.clone();
        let mut exit_rx = self.auxiliary_exit_tx.subscribe();
        let mut shutdown_rx = self.session_reaper_shutdown.subscribe();

        let mut group = self.task_group.lock().await;
        group.spawn_critical("auxiliary_reaper", async move {
            loop {
                tokio::select! {
                    event = exit_rx.recv() => {
                        match event {
                            Ok(exit) => {
                                let removed = {
                                    let mut aux = transport.auxiliary_tasks.lock().await;
                                    aux.remove(&exit.task_id)
                                };
                                match removed {
                                    Some(AuxiliaryRegistryEntry::Running(task)) => {
                                        match task.handle.await {
                                            Ok(_) => {
                                                tracing::debug!(
                                                    "Auxiliary reaper joined handle for task {} ({:?})",
                                                    exit.task_id,
                                                    exit.reason
                                                );
                                            }
                                            Err(error) if error.is_panic() => {
                                                tracing::warn!(
                                                    "Auxiliary reaper: task {} panicked after exit event",
                                                    exit.task_id
                                                );
                                            }
                                            Err(error) => {
                                                tracing::debug!(
                                                    "Auxiliary reaper: task {} cancelled after exit: {}",
                                                    exit.task_id,
                                                    error
                                                );
                                            }
                                        }
                                    }
                                    None => {}
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Auxiliary reaper lagged by {} events, scanning", n);
                                transport.reap_finished_auxiliary_tasks().await;
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::debug!("Auxiliary reaper received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Scan auxiliary_tasks for completed handles and remove them (Iteration 74, Phase 21).
    ///
    /// Handles the case where the broadcast reaper lagged and missed exit events.
    /// Finished handles are joined outside the lock to avoid holding it during await.
    async fn reap_finished_auxiliary_tasks(&self) {
        let mut to_join = Vec::new();
        {
            let mut aux = self.auxiliary_tasks.lock().await;
            let mut to_remove = Vec::new();
            for (task_id, entry) in aux.iter() {
                match entry {
                    AuxiliaryRegistryEntry::Running(task) => {
                        if task.handle.is_finished() {
                            to_remove.push(*task_id);
                        }
                    }
                }
            }
            for task_id in to_remove {
                if let Some(entry) = aux.remove(&task_id) {
                    if let AuxiliaryRegistryEntry::Running(task) = entry {
                        to_join.push(task);
                    }
                }
            }
        }
        for task in to_join {
            match task.handle.await {
                Ok(_) => {
                    tracing::debug!(
                        "Auxiliary reaper lag recovery: joined finished task {}",
                        task.task_id
                    );
                }
                Err(error) if error.is_panic() => {
                    tracing::warn!(
                        "Auxiliary reaper lag recovery: task {} panicked",
                        task.task_id
                    );
                }
                Err(error) => {
                    tracing::debug!(
                        "Auxiliary reaper lag recovery: task {} cancelled: {}",
                        task.task_id,
                        error
                    );
                }
            }
        }
    }

    /// Restore a staged peer resource's topology and DHT state to pre-mutation
    /// values (Iteration 74, Phase 1).
    ///
    /// Used by both `rollback_startup()` and `recover_failed_state()` to avoid
    /// duplicated restoration logic. Idempotent: restoring an already-restored
    /// entry is success.
    async fn restore_peer_logical_state(&self, peer: &StagedPeerResource) -> Result<(), String> {
        // Restore topology state
        match &peer.previous_topology {
            None => {
                // New peer - remove the entry entirely
                self.topology.remove_peer(&peer.node_id).await;
            }
            Some(snapshot) => {
                // Existing peer was overwritten - restore exact native state
                self.topology
                    .restore_peer_state(snapshot.peer_state.clone())
                    .await;
            }
        }

        // Restore DHT state
        match &peer.dht_mutation {
            DhtPeerMutation::None => {
                // No mutation to undo
            }
            DhtPeerMutation::Created => {
                // Remove the new routing entry
                if let Some(ref rm) = self.routing_manager {
                    rm.remove_peer(&peer.node_id).await;
                    tracing::debug!(
                        "Removed DHT routing entry for peer {} during restoration",
                        peer.node_id
                    );
                }
            }
            DhtPeerMutation::Previous(snapshot) => {
                // Restore the previous routing entry
                if let Some(ref rm) = self.routing_manager {
                    rm.restore_peer(snapshot)
                        .await
                        .map_err(|e| format!("DHT restore failed for {}: {}", peer.node_id, e))?;
                    tracing::debug!(
                        "Restored DHT routing entry for peer {} during restoration",
                        peer.node_id
                    );
                }
            }
        }

        Ok(())
    }

    /// Restore a peer's logical topology and DHT state, then verify the
    /// restoration succeeded. Returns `Ok(())` only when both restoration
    /// and verification pass.
    async fn restore_and_verify_peer_logical_state(
        &self,
        peer: &StagedPeerResource,
    ) -> Result<(), String> {
        // Step 1: Restore
        self.restore_peer_logical_state(peer).await?;

        // Step 2: Verify topology
        if let Some(ref snapshot) = peer.previous_topology {
            if !self.topology.topology_matches_snapshot(snapshot).await {
                return Err(format!(
                    "Topology verification failed after restoration for peer {}",
                    peer.node_id
                ));
            }
        } else {
            // New peer — should be absent
            if !self.topology.peer_absent(&peer.node_id).await {
                return Err(format!(
                    "New peer {} still present after restoration (expected absent)",
                    peer.node_id
                ));
            }
        }

        // Step 3: Verify DHT
        if let Some(ref rm) = self.routing_manager {
            match &peer.dht_mutation {
                crate::lifecycle::DhtPeerMutation::Previous(ref snapshot) => {
                    if !rm.peer_matches_snapshot(snapshot).await {
                        return Err(format!(
                            "DHT verification failed after restoration for peer {}",
                            peer.node_id
                        ));
                    }
                }
                crate::lifecycle::DhtPeerMutation::Created => {
                    if !rm.peer_absent(&peer.node_id).await {
                        return Err(format!(
                            "New DHT entry for peer {} still present after restoration",
                            peer.node_id
                        ));
                    }
                }
                crate::lifecycle::DhtPeerMutation::None => {}
            }
        }

        Ok(())
    }

    /// Rollback a failed startup: close connections, stop sessions and
    /// auxiliary tasks, then restore topology/DHT state.
    ///
    /// The critical ordering guarantee (Iteration 75, Part C):
    /// **Physical teardown (connections, sessions, auxiliary tasks) completes
    /// BEFORE logical restoration (topology, DHT).** This prevents late peer
    /// session writes from invalidating the restored state.
    ///
    /// Returns a `RollbackReport` indicating whether cleanup completed cleanly.
    async fn rollback_startup(&self, stage: &mut MeshStartupStage) -> RollbackReport {
        tracing::warn!("Rolling back mesh startup");
        let mut report = RollbackReport::default();

        // Phase 1: Signal shutdown to all staged tasks
        stage.task_group.begin_shutdown().await;

        // Phase 2: Close attempt-created QUIC connections
        for peer in &stage.created_peers {
            if peer.connection_inserted {
                if let Some(entry) = self.peer_connections.get(&peer.session_id) {
                    entry
                        .value()
                        .connection
                        .close(0u32.into(), b"Startup rollback");
                    report.peer_connections_closed += 1;
                }
                self.peer_connections.remove(&peer.session_id);
            }
        }

        // Phase 3: Use a single deadline for all cleanup phases
        let rollback_timeout =
            Duration::from_secs(self.config.connection.startup_rollback_timeout_secs);
        let deadline = std::time::Instant::now() + rollback_timeout;

        // Phase 4: Stop staged peer sessions and auxiliary tasks BEFORE logical
        // restoration. This is the Iteration 75 invariant: no peer/session/auxiliary
        // task that can mutate topology or DHT remains live before restoration begins.
        for peer in &stage.created_peers {
            self.stop_staged_peer_activity(peer, deadline, &mut report)
                .await;
        }

        // Phase 5: Always finalize staged tasks. A zero remaining budget changes
        // cleanup from drain to forced abort, but it never permits skipping
        // ownership finalization (Iteration 76, Part A). `join_all(ZERO)` takes
        // its zero-budget branch internally: abort-and-await each task with
        // synthetic `Aborted` exits.
        let exits = stage.task_group.join_all(remaining(deadline)).await;
        report.tasks_joined = exits.len();

        for exit in &exits {
            if exit.is_fatal() {
                report.errors.push(format!(
                    "Task '{}' exited fatally during rollback: {}",
                    exit.name, exit.reason
                ));
            }
        }

        // Count tasks that were forcibly aborted from the exit metadata
        let tasks_aborted_from_exits = exits
            .iter()
            .filter(|exit| matches!(exit.reason, MeshTaskExitReason::Aborted))
            .count();
        report.tasks_aborted += tasks_aborted_from_exits;

        // Phase 6: Restore and verify logical state. Safe because all peer
        // sessions and auxiliary tasks that could mutate this state have been
        // stopped in Phase 4 (Iteration 75 invariant).
        for peer in &stage.created_peers {
            match self.restore_and_verify_peer_logical_state(peer).await {
                Ok(()) => {
                    report.topology_entries_restored += 1;
                }
                Err(error) => {
                    tracing::error!(
                        "Failed to restore/verify logical state for peer {}: {}",
                        peer.node_id,
                        error
                    );
                    report.errors.push(error);
                    report.unresolved_peers.push(peer.clone());
                }
            }
        }

        // Phase 8: Active runtime cleanup
        if stage.runtime_started {
            if let Some(ref runtime) = self.runtime {
                runtime.stop_server().await;
                report.runtime_stopped = true;
                tracing::debug!("QUIC runtime stopped during rollback");
            }
        }

        // Phase 8.5: Rollback DHT routing initialization if it was newly
        // created during this startup attempt (Iteration 87, Phase 4).
        // If the table was already initialized before this attempt, preserve it.
        if let Some(ref snapshot) = stage.dht_init_snapshot {
            if snapshot.was_initialized_this_attempt {
                if let Some(ref rm) = self.routing_manager {
                    rm.clear_routing_table().await;
                    tracing::info!(
                        "DHT routing table cleared during rollback (was newly initialized)"
                    );
                }
            }
        }

        // Phase 9: Reset accept-loop report for diagnostics and future generations
        if stage.runtime_started {
            let mut ar = self.accept_loop_report.lock().await;
            ar.drained_handshakes = 0;
            ar.aborted_handshakes = 0;
            ar.rejected_at_capacity = 0;
            // Don't increment generation here - that happens at next startup
        }

        report.clean = report.errors.is_empty();
        report
    }

    /// Stop all activity for a single staged peer during rollback.
    ///
    /// Must be called BEFORE logical restoration (topology/DHT) to satisfy
    /// the Iteration 75 invariant: no session or auxiliary task that can
    /// mutate topology or DHT remains live before restoration begins.
    ///
    /// This method:
    /// 1. Cancels session-bound auxiliary tasks (e.g., preflight queries)
    /// 2. Drains/aborts the peer session task with the shared deadline
    async fn stop_staged_peer_activity(
        &self,
        peer: &StagedPeerResource,
        deadline: std::time::Instant,
        report: &mut RollbackReport,
    ) {
        // Cancel auxiliary tasks for this session first — they may be
        // performing topology/DHT reads or writes.
        if let Some(ref _task_id) = peer.session_task_id {
            self.cancel_auxiliary_tasks_for_sessions(&[peer.session_id.clone()])
                .await;
        }

        // Stop the peer session with deadline-bounded drain. A zero remaining
        // budget changes cleanup from drain to forced abort, but it never
        // permits skipping ownership finalization (Iteration 76, Part A/B).
        //
        // We always send the cooperative shutdown signal first; then we wait
        // for the parent to return within the remaining budget. If the
        // budget is exhausted before cooperative return, we abort the parent
        // and surface that as incomplete cleanup (Phase 11).
        if peer.session_task_id.is_some() {
            let task = {
                let mut sessions = self.peer_sessions.lock().await;
                sessions.remove(&peer.session_id)
            };
            if let Some(task) = task {
                // Signal cooperative cancellation so the session's loop can
                // run its child stream handler drain path before parent
                // return (Iteration 76, Phase 6-9).
                let _ = task.shutdown_tx.send(true);

                let left = remaining(deadline);
                let outcome = Self::stop_peer_session_task(task.handle, left, Some(report)).await;
                match outcome {
                    PeerSessionStopOutcome::Drained(_) => {}
                    PeerSessionStopOutcome::ForcedParentAbort => {
                        report.errors.push(format!(
                            "Peer session {} (gen {}, node {}) required parent abort; \
                             child stream cleanup could not be proven cooperative",
                            peer.session_id, peer.session_generation, peer.node_id
                        ));
                    }
                    PeerSessionStopOutcome::Failed(error) => {
                        report.errors.push(format!(
                            "Peer session {} (gen {}, node {}) failed during stop: {}",
                            peer.session_id, peer.session_generation, peer.node_id, error
                        ));
                    }
                }
            }
        }
    }

    /// Force-abort a peer session parent task and classify the outcome
    /// (Iteration 77, Phase 12).
    ///
    /// Used for both zero-budget and cooperative-timeout paths to ensure
    /// identical classification. A cancelled `JoinError` is the expected
    /// result of `abort()` and maps to `ForcedParentAbort`, not `Failed`.
    async fn force_abort_peer_session(
        mut handle: tokio::task::JoinHandle<()>,
    ) -> PeerSessionStopOutcome {
        handle.abort();
        match handle.await {
            Err(err) if err.is_panic() => PeerSessionStopOutcome::Failed(format!(
                "peer-session parent panicked during forced abort: {err}"
            )),
            _ => PeerSessionStopOutcome::ForcedParentAbort,
        }
    }

    /// Stop a single peer session task with cooperative cancellation, falling
    /// back to forced parent abort only if the cooperative return does not
    /// complete within the supplied budget (Iteration 76, Phase 10).
    ///
    /// Invariant: `handle` is always awaited (cooperatively, on cancellation,
    /// or after a forced abort). The returned `PeerSessionStopOutcome` lets
    /// the caller distinguish a clean cooperative return from a forced
    /// parent abort (which cannot prove the child stream-handler `JoinSet`
    /// was drained through the normal path).
    ///
    /// `report` may be `None` for callers that already maintain their own
    /// session accounting (e.g., recovery and shutdown paths).
    async fn stop_peer_session_task(
        handle: tokio::task::JoinHandle<()>,
        budget: std::time::Duration,
        mut report: Option<&mut RollbackReport>,
    ) -> PeerSessionStopOutcome {
        let mut handle = handle;

        if budget.is_zero() {
            // No cooperative budget remaining — forced abort (Iteration 77,
            // Phase 11). Use the shared helper for consistent classification.
            if let Some(r) = report.as_deref_mut() {
                r.peer_sessions_aborted += 1;
                r.tasks_aborted += 1;
            }
            return Self::force_abort_peer_session(handle).await;
        }

        // Attempt cooperative cancellation first. The session's
        // peer_message_loop is expected to observe the shutdown_tx signal,
        // stop accepting new streams, and run its child JoinSet drain path
        // before returning.
        let sleep = tokio::time::sleep(budget);
        tokio::pin!(sleep);
        let result = tokio::select! {
            join = &mut handle => Ok(join),
            _ = &mut sleep => Err(()),
        };

        match result {
            Ok(Ok(())) => {
                if let Some(r) = report.as_deref_mut() {
                    r.peer_sessions_drained += 1;
                }
                PeerSessionStopOutcome::Drained(crate::lifecycle::PeerSessionExitReason::Cancelled)
            }
            Ok(Err(err)) if err.is_panic() => {
                if let Some(r) = report.as_deref_mut() {
                    r.peer_sessions_failed += 1;
                }
                PeerSessionStopOutcome::Failed("parent panic".to_string())
            }
            Ok(Err(_)) => {
                if let Some(r) = report.as_deref_mut() {
                    r.peer_sessions_failed += 1;
                }
                PeerSessionStopOutcome::Failed("parent cancelled".to_string())
            }
            Err(()) => {
                // Cooperative return did not complete in the budget; forced
                // parent abort (Iteration 77, Phase 12). Use the shared
                // helper for consistent classification.
                if let Some(r) = report.as_deref_mut() {
                    r.peer_sessions_aborted += 1;
                    r.tasks_aborted += 1;
                }
                Self::force_abort_peer_session(handle).await
            }
        }
    }
}

impl MeshTransport {
    /// Verify that rollback completed successfully by checking that no
    /// staged resources remain live.
    async fn verify_rollback_complete(&self, stage: &MeshStartupStage) -> Vec<String> {
        let mut issues = Vec::new();

        // Check that all staged peer connections were removed
        for peer in &stage.created_peers {
            if peer.connection_inserted && self.peer_connections.contains_key(&peer.session_id) {
                issues.push(format!(
                    "Peer connection for session {} still present after rollback",
                    peer.session_id
                ));
            }
        }

        // Check that no staged session IDs remain in the session-task registry
        {
            let sessions = self.peer_sessions.lock().await;
            for peer in &stage.created_peers {
                if let Some(ref task_id) = peer.session_task_id {
                    if sessions.contains_key(&peer.session_id) {
                        issues.push(format!(
                            "Peer session {} (task {}) still present in registry after rollback",
                            peer.session_id, task_id
                        ));
                    }
                }
            }
        }

        // Check that running projection is false
        if self.running_projection.load(Ordering::SeqCst) {
            issues.push("running_projection is still true after rollback".to_string());
        }

        // Check lifecycle is not Running
        {
            let state = self.lifecycle_state.lock().await;
            if matches!(*state, MeshLifecycleState::Running) {
                issues.push("lifecycle state is Running after rollback".to_string());
            }
        }

        issues
    }

    /// Cancel auxiliary tasks associated with the given session IDs.
    ///
    /// Called during rollback to ensure auxiliary tasks (e.g., preflight route
    /// queries) do not outlive the peer sessions they were spawned for (Phase 14).
    async fn cancel_auxiliary_tasks_for_sessions(&self, session_ids: &[String]) {
        let mut aux = self.auxiliary_tasks.lock().await;
        let to_remove: Vec<MeshTaskId> = aux
            .iter()
            .filter(|(_, entry)| {
                entry
                    .session_id()
                    .is_some_and(|sid| session_ids.contains(&sid.to_string()))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            if let Some(entry) = aux.remove(&id) {
                if let AuxiliaryRegistryEntry::Running(task) = entry {
                    task.handle.abort();
                    let _ = task.handle.await;
                }
            }
        }
    }

    /// Complete a failed startup by transitioning to `Stopped` (if rollback
    /// was clean) or `Failed` (if rollback itself had issues).
    async fn finish_failed_startup(&self, rollback: &RollbackReport) {
        let mut state = self.lifecycle_state.lock().await;
        if rollback.clean {
            // Successful rollback -> Stopped (safe to retry)
            state.transition_to_stopped();
            tracing::info!("Mesh startup rolled back cleanly; lifecycle: stopped");
        } else {
            // Incomplete rollback -> Failed (operator intervention needed)
            state.transition_to_failed();
            tracing::warn!(
                "Mesh startup rolled back with errors; lifecycle: failed ({} errors)",
                rollback.errors.len()
            );
        }
    }

    /// Recover from a `Failed` lifecycle state by re-running cleanup
    /// and transitioning back to `Stopped`.
    ///
    /// This method:
    /// 1. Acquires the lifecycle operation lock
    /// 2. Verifies current state is `Failed`
    /// 3. Re-runs cleanup against any remaining resources
    /// 4. Verifies no owned tasks/sessions/connections remain
    /// 5. Transitions to `Stopped` only after successful verification
    pub async fn recover_failed_state(&self, timeout: Duration) -> Result<(), MeshTransportError> {
        let _lifecycle_guard = self.lifecycle_op.lock().await;
        let deadline = std::time::Instant::now() + timeout;

        // Verify current state is Failed
        {
            let state = self.lifecycle_state.lock().await;
            if !matches!(*state, MeshLifecycleState::Failed) {
                return Err(MeshTransportError::LifecycleConflict(format!(
                    "Cannot recover: current state is {state}, expected Failed"
                )));
            }
        }

        tracing::info!(
            "Attempting recovery from Failed lifecycle state (timeout: {:?})",
            timeout
        );

        // Phase 1: Signal shutdown intent
        self.shutdown_started.store(true, Ordering::SeqCst);

        // Phase 2: Signal the top-level MeshTaskGroup
        {
            let group = self.task_group.lock().await;
            group.begin_shutdown().await;
        }

        // Signal session and auxiliary reapers to exit (Iteration 74, Phase 14/20)
        let _ = self.session_reaper_shutdown.send(true);

        // Phase 3: Stop the QUIC runtime/endpoint
        if let Some(ref runtime) = self.runtime {
            runtime.stop_server().await;
        }

        // Phase 4: Close all peer connections
        for entry in self.peer_connections.iter() {
            entry
                .value()
                .connection
                .close(0u32.into(), b"Recovery cleanup");
        }
        self.peer_connections.clear();

        // Phase 5: Drain/abort/await peer sessions using the shared
        // `stop_peer_session_task` helper (Iteration 76, Phase 10). A zero
        // remaining budget changes cleanup to forced abort, but the
        // JoinHandle is always awaited and forced parent abort is reported
        // as incomplete cleanup.
        let mut session_errors: Vec<String> = Vec::new();
        {
            let mut sessions = self.peer_sessions.lock().await;
            let session_keys: Vec<String> = sessions.keys().cloned().collect();
            for key in session_keys {
                if let Some(task) = sessions.remove(&key) {
                    // Always signal cooperative cancellation first.
                    let _ = task.shutdown_tx.send(true);

                    // Phase 14: capture generation and node_id before task
                    // is consumed by stop_peer_session_task
                    let session_gen = task.generation;
                    let session_node_id = task.node_id.clone();

                    let left = remaining(deadline);
                    let outcome = Self::stop_peer_session_task(task.handle, left, None).await;
                    match outcome {
                        PeerSessionStopOutcome::Drained(_) => {}
                        PeerSessionStopOutcome::ForcedParentAbort => {
                            session_errors.push(format!(
                                "Recovery: peer session {} (gen {}, node {}) required parent abort; \
                                 child stream cleanup could not be proven cooperative",
                                key, session_gen, session_node_id
                            ));
                        }
                        PeerSessionStopOutcome::Failed(error) => {
                            session_errors.push(format!(
                                "Recovery: peer session {} (gen {}, node {}) failed during stop: {}",
                                key, session_gen, session_node_id, error
                            ));
                        }
                    }
                }
            }
        }

        // Phase 6: Drain/abort/await the top-level task group. A zero
        // remaining budget is fine: join_all(ZERO) takes its zero-budget
        // branch (abort + await + synthetic Aborted exit).
        {
            let task_remaining = remaining(deadline);
            let mut group = self.task_group.lock().await;
            let _exits = group.join_all(task_remaining).await;
        }

        // Phase 7: Apply retained residue before clearing (Iteration 74, Phase 2-3)
        let residue = {
            let mut guard = self.failed_startup_residue.lock().await;
            guard.take()
        };

        let mut remaining_peers: Vec<StagedPeerResource> = Vec::new();
        let mut remaining_errors: Vec<String> = Vec::new();

        if let Some(residue) = residue {
            for peer in &residue.peers {
                match self.restore_and_verify_peer_logical_state(peer).await {
                    Ok(()) => {
                        // Successfully restored - also close connection if still present
                        if peer.connection_inserted {
                            if let Some((_key, peer_conn)) =
                                self.peer_connections.remove(&peer.session_id)
                            {
                                peer_conn
                                    .connection
                                    .close(0u32.into(), b"Recovery residue cleanup");
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            "Recovery: failed to restore/verify peer {}: {}",
                            peer.node_id,
                            error
                        );
                        remaining_peers.push(peer.clone());
                        if !remaining_errors.contains(&error) {
                            remaining_errors.push(error);
                        }
                    }
                }
            }

            // Retain residue if any peers are unresolved
            if !remaining_peers.is_empty() {
                *self.failed_startup_residue.lock().await = Some(FailedStartupResidue {
                    peers: remaining_peers,
                    generation: residue.generation,
                    runtime_started: residue.runtime_started,
                    rollback_errors: {
                        let mut errors = residue.rollback_errors;
                        errors.extend(remaining_errors.clone());
                        errors.dedup();
                        errors
                    },
                });
            }
        }

        // Phase 8: Clear auxiliary tasks.
        // Acquire submission lock first to prevent new submissions during drain.
        {
            let _aux_submission_guard = self.auxiliary_submission_lock.lock().await;
            let mut aux = self.auxiliary_tasks.lock().await;
            for (_id, entry) in aux.drain() {
                let AuxiliaryRegistryEntry::Running(task) = entry;
                task.handle.abort();
                let _ = task.handle.await;
            }
        }

        // Phase 9: Clear accept-loop report
        {
            let mut report = self.accept_loop_report.lock().await;
            report.drained_handshakes = 0;
            report.aborted_handshakes = 0;
            report.rejected_at_capacity = 0;
        }

        // Clear running projection
        self.running_projection.store(false, Ordering::SeqCst);

        // Phase 10: Full verification
        let mut issues = Vec::new();
        issues.extend(session_errors);
        issues.extend(remaining_errors);

        // Verify task group is empty
        {
            let group = self.task_group.lock().await;
            let (c, b, ch) = group.active_count();
            if c + b + ch > 0 {
                issues.push(format!(
                    "task group not empty: {c} critical, {b} background, {ch} children"
                ));
            }
        }

        // Verify peer-session registry is empty
        {
            let sessions = self.peer_sessions.lock().await;
            if !sessions.is_empty() {
                issues.push(format!("{} peer sessions still present", sessions.len()));
            }
        }

        // Verify peer connections are empty
        if !self.peer_connections.is_empty() {
            issues.push(format!(
                "{} peer connections still present",
                self.peer_connections.len()
            ));
        }

        // Verify auxiliary tasks are empty
        {
            let aux = self.auxiliary_tasks.lock().await;
            if !aux.is_empty() {
                issues.push(format!("{} auxiliary tasks still present", aux.len()));
            }
        }

        // Verify failed-startup residue is cleared
        {
            let residue = self.failed_startup_residue.lock().await;
            if residue.is_some() {
                issues.push("failed_startup_residue is still present".to_string());
            }
        }

        // Verify running projection is clear
        if self.running_projection.load(Ordering::SeqCst) {
            issues.push("running_projection is still true".to_string());
        }

        // Verify lifecycle is not Running
        {
            let state = self.lifecycle_state.lock().await;
            if matches!(*state, MeshLifecycleState::Running) {
                issues.push("lifecycle state is Running".to_string());
            }
        }

        if issues.is_empty() {
            let mut state = self.lifecycle_state.lock().await;
            state.transition_to_stopped();
            self.shutdown_started.store(false, Ordering::SeqCst);
            tracing::info!("Recovery from Failed state complete; lifecycle: stopped");
            Ok(())
        } else {
            tracing::warn!("Recovery incomplete: {:?}", issues);
            Err(MeshTransportError::StartupRollbackFailed {
                startup_error: "Recovery from Failed state".to_string(),
                rollback_errors: issues,
            })
        }
    }

    /// Roll back a failed startup and return an appropriate error.
    ///
    /// If rollback completed cleanly, returns the original startup error.
    /// If rollback itself had errors, returns `StartupRollbackFailed` with
    /// both the original error and the rollback errors.
    async fn rollback_and_return<T>(
        &self,
        stage: &mut MeshStartupStage,
        startup_error: MeshTransportError,
    ) -> Result<T, MeshTransportError> {
        let mut rollback = self.rollback_startup(stage).await;

        // Verify rollback completeness and merge into rollback result BEFORE lifecycle selection
        let verification_issues = self.verify_rollback_complete(stage).await;
        for issue in &verification_issues {
            tracing::error!("Rollback verification failed: {}", issue);
        }
        rollback.errors.extend(verification_issues);
        rollback.clean = rollback.errors.is_empty();

        // Store failed-startup residue if rollback was incomplete (Phase 8)
        if !rollback.clean {
            let residue = FailedStartupResidue {
                peers: rollback.unresolved_peers.clone(),
                generation: self.accept_loop_report.lock().await.generation,
                runtime_started: stage.runtime_started,
                rollback_errors: rollback.errors.clone(),
            };
            *self.failed_startup_residue.lock().await = Some(residue);
        }

        // Lifecycle selection now reflects actual cleanup reality
        self.finish_failed_startup(&rollback).await;

        if rollback.clean {
            Err(startup_error)
        } else {
            Err(MeshTransportError::StartupRollbackFailed {
                startup_error: startup_error.to_string(),
                rollback_errors: rollback.errors,
            })
        }
    }

    #[allow(dead_code)]
    async fn mesh_accept_loop(
        self: Arc<MeshTransport>,
        mut incoming: mpsc::Receiver<synvoid_tunnel::quic::runtime::IncomingConnection>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let max_handshakes = self.config.connection.max_concurrent_handshakes;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_handshakes));
        let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                biased;
                Some(incoming_conn) = incoming.recv() => {
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(
                                "Rejecting incoming connection: at capacity ({max_handshakes} active handshakes)"
                            );
                            drop(incoming_conn);
                            continue;
                        }
                    };
                    let transport = self.clone();
                    children.spawn(async move {
                        let _permit = permit;
                        if let Err(e) = transport.handle_incoming_peer_connection(incoming_conn).await {
                            tracing::warn!("Failed to handle incoming peer connection: {}", e);
                        }
                    });
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Mesh accept loop shutting down, draining {} child tasks", children.len());
                        let drain_timeout = Duration::from_secs(10);
                        let deadline = tokio::time::Instant::now() + drain_timeout;
                        let mut drained = 0usize;
                        let mut aborted = 0usize;
                        while !children.is_empty() {
                            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                            if remaining.is_zero() {
                                let remaining_count = children.len();
                                tracing::warn!("Aborting {} remaining peer children", remaining_count);
                                children.abort_all();
                                let _ = children.join_all().await;
                                aborted += remaining_count;
                                break;
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(remaining) => {
                                    let remaining_count = children.len();
                                    tracing::warn!("Aborting {} remaining peer children after timeout", remaining_count);
                                    children.abort_all();
                                    let _ = children.join_all().await;
                                    aborted += remaining_count;
                                    break;
                                }
                                Some(_) = children.join_next() => {
                                    drained += 1;
                                }
                            }
                        }
                        // Publish accept loop report
                        {
                            let mut report = self.accept_loop_report.lock().await;
                            report.drained_handshakes = drained;
                            report.aborted_handshakes = aborted;
                        }
                        tracing::info!("Mesh accept loop stopped (drained: {drained}, aborted: {aborted})");
                        break;
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    async fn handle_incoming_peer_connection(
        &self,
        incoming: synvoid_tunnel::quic::runtime::IncomingConnection,
    ) -> Result<(), MeshTransportError> {
        let remote_addr = incoming.remote_addr;
        let connection = incoming.connection;

        tracing::debug!("Accepted incoming connection from {}", remote_addr);

        let handshake_timeout = Duration::from_secs(self.config.connection.handshake_timeout_secs);

        let (mut send_stream, mut recv_stream) =
            tokio::time::timeout(handshake_timeout, connection.accept_bi())
                .await
                .map_err(|_| MeshTransportError::Timeout)?
                .map_err(|e| {
                    MeshTransportError::ConnectionFailed(format!("Accept bi failed: {}", e))
                })?;

        let mut len_buf = [0u8; 4];
        tokio::time::timeout(handshake_timeout, recv_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| MeshTransportError::Timeout)?
            .map_err(|e| MeshTransportError::ReceiveFailed(format!("Read length failed: {}", e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE || len == 0 {
            return Err(MeshTransportError::ReceiveFailed(format!(
                "Invalid message length: {} (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }
        let mut hello_buf = vec![0u8; len];
        tokio::time::timeout(handshake_timeout, recv_stream.read_exact(&mut hello_buf))
            .await
            .map_err(|_| MeshTransportError::Timeout)?
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
                if let Err(e) = crate::peer_auth::validate_peer_role(
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
                    None,
                    false,
                ) {
                    tracing::warn!("Node verification failed for {}: {}", node_id, e);
                    return Err(MeshTransportError::AuthFailed(e));
                }

                let upstreams_map: HashMap<String, crate::protocol::UpstreamInfo> =
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
        let upstreams_internal: HashMap<String, crate::protocol::UpstreamInfo> = upstreams
            .into_iter()
            .map(|u| (u.upstream_id.clone(), u))
            .collect();

        let hello_ack = MeshMessage::HelloAck {
            version: MESH_MESSAGE_VERSION,
            node_id: self.config.node_id().into(),
            role: self.config.role,
            session_id: session_id.clone().into(),
            capabilities: crate::protocol::MeshCapabilities::from_config(
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

        let peer_info = crate::protocol::MeshPeerInfo {
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

        self.verify_peer_connection_certificate_if_available(&peer_node_id, &connection)?;

        let peer_connection = crate::transport_types::MeshPeerConnection {
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
                crate::protocol::ReplayProtection::new(),
            )),
            stream_pool: Arc::new(tokio::sync::Mutex::new(
                crate::transport_types::MeshStreamPool::new(Some(connection.clone())),
            )),
        };

        self.topology
            .add_peer(peer_info.clone(), crate::topology::PeerStatus::Healthy)
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
        let session_id_for_loop = session_id.clone();
        let peer_node_id_for_loop = peer_node_id.clone();
        let exit_tx = self.session_exit_tx.clone();
        let gen = self.session_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let handle_gen = gen;
        // Cooperative cancellation channel (Iteration 76, Phase 6).
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            let exit = transport
                .peer_message_loop(
                    session_id_for_loop,
                    peer_node_id_for_loop,
                    connection,
                    topo,
                    handle_gen,
                    shutdown_rx,
                )
                .await;
            let _ = exit_tx.send(exit);
        });
        let mut sessions = self.peer_sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            PeerSessionTask {
                session_id: session_id.clone(),
                node_id: peer_node_id,
                handle,
                generation: gen,
                shutdown_tx,
            },
        );

        Ok(())
    }

    pub async fn stop(&self) {
        self.shutdown_with_timeout(Duration::from_secs(30)).await;
    }

    /// Performs a bounded shutdown with the given timeout.
    ///
    /// Returns a report describing which tasks were cleanly joined, which
    /// were aborted, and peer-child drainage statistics.
    ///
    /// All shutdown phases share one deadline derived from the caller's
    /// timeout. No phase applies a fresh fixed timeout.
    pub async fn shutdown_with_timeout(&self, timeout: Duration) -> MeshShutdownReport {
        let deadline = std::time::Instant::now() + timeout;

        // Serialize lifecycle transitions
        let _lifecycle_guard = self.lifecycle_op.lock().await;

        // Transition to Stopping
        {
            let mut state = self.lifecycle_state.lock().await;
            if !state.can_stop() {
                tracing::warn!(
                    "Mesh shutdown requested but state is {}; returning empty report",
                    *state
                );
                return MeshShutdownReport::default();
            }
            state.transition_to_stopping().ok();
        }

        // Clear running projection
        self.running_projection.store(false, Ordering::SeqCst);

        // Signal shutdown to all tasks
        self.shutdown_started.store(true, Ordering::SeqCst);
        {
            let group = self.task_group.lock().await;
            group.begin_shutdown().await;
        }

        // Also send on the legacy broadcast channel
        if let Some(tx) = self.shutdown_tx.write().take() {
            let _ = tx.send(());
        }

        // Signal session and auxiliary reapers to exit (Iteration 74, Phase 14/20)
        let _ = self.session_reaper_shutdown.send(true);

        // Close all QUIC connections
        for entry in self.peer_connections.iter() {
            entry
                .value()
                .connection
                .close(0u32.into(), b"Mesh shutdown");
        }
        let peers_at_shutdown_start = self.peer_connections.len();
        self.peer_connections.clear();

        // Drain auxiliary tasks (Iteration 73, Phase 13-14).
        // Acquire submission lock first to prevent new submissions during drain.
        {
            let _aux_submission_guard = self.auxiliary_submission_lock.lock().await;
            let mut aux = self.auxiliary_tasks.lock().await;
            for (_id, entry) in aux.drain() {
                let AuxiliaryRegistryEntry::Running(task) = entry;
                task.handle.abort();
                let _ = task.handle.await;
            }
        }

        // Join all tasks with the shared deadline
        let task_timeout = remaining(deadline);
        let mut group = self.task_group.lock().await;
        let exits = group.join_all(task_timeout).await;
        drop(group);

        // Drain peer sessions with the shared deadline (Iteration 76, Phase 10)
        // using the shared `stop_peer_session_task` helper. Always signal
        // cooperative cancellation first; only fall back to forced parent
        // abort if the cooperative return does not complete in time.
        let mut sessions = self.peer_sessions.lock().await;
        let mut drained = 0;
        let mut aborted = 0;
        let mut failed = 0;
        let session_keys: Vec<String> = sessions.keys().cloned().collect();

        for key in session_keys {
            if let Some(task) = sessions.remove(&key) {
                // Always signal cooperative cancellation first.
                let _ = task.shutdown_tx.send(true);

                let left = remaining(deadline);
                let outcome = Self::stop_peer_session_task(task.handle, left, None).await;
                match outcome {
                    PeerSessionStopOutcome::Drained(_) => drained += 1,
                    PeerSessionStopOutcome::ForcedParentAbort => aborted += 1,
                    PeerSessionStopOutcome::Failed(_) => failed += 1,
                }
            }
        }
        drop(sessions);

        // Include accept loop report in shutdown report (Iteration 74, Phase 29-30)
        let accept_report = self.accept_loop_report.lock().await.clone();
        let current_gen = self.startup_generation.load(Ordering::SeqCst);
        let report_is_fresh = if current_gen == 0 {
            // No startup yet; accept-loop report is not meaningful
            false
        } else if accept_report.generation == current_gen {
            true
        } else {
            tracing::warn!(
                "Accept-loop report generation mismatch: report={}, current={}; counts suppressed",
                accept_report.generation,
                current_gen
            );
            false
        };

        // Build report
        let mut report = MeshShutdownReport::default();
        report.peers_at_shutdown_start = peers_at_shutdown_start;
        report.remaining_peers = self.peer_connections.len();
        report.drained_peer_sessions = drained;
        report.aborted_peer_sessions = aborted;
        report.failed_peer_sessions = failed;
        report.stream_handler_drain = crate::lifecycle::PeerStreamDrainReport {
            drained: self.aggregate_handler_drained.swap(0, Ordering::Relaxed),
            aborted: self.aggregate_handler_aborted.swap(0, Ordering::Relaxed),
            failed: self.aggregate_handler_failed.swap(0, Ordering::Relaxed),
        };
        report.accept_loop_report = if report_is_fresh {
            Some(accept_report.clone())
        } else {
            None
        };
        for exit in &exits {
            match exit.reason {
                crate::lifecycle::MeshTaskExitReason::Aborted => {
                    report.aborted_tasks.push(exit.clone());
                }
                crate::lifecycle::MeshTaskExitReason::CleanCompletion
                | crate::lifecycle::MeshTaskExitReason::Cancelled => {
                    report.clean_tasks += 1;
                }
                _ => {
                    report.failed_tasks.push(exit.clone());
                }
            }
        }

        // Phase 31: Reset accept-loop report counts after consuming
        if report_is_fresh {
            let mut ar = self.accept_loop_report.lock().await;
            ar.drained_handshakes = 0;
            ar.aborted_handshakes = 0;
            ar.rejected_at_capacity = 0;
            // Retain generation for diagnostics but mark consumed
        }

        // Transition to Stopped
        {
            let mut state = self.lifecycle_state.lock().await;
            state.transition_to_stopped();
        }

        tracing::info!(
            "Mesh transport stopped (clean={}, failed={}, aborted={}, duration={:?})",
            report.clean_tasks,
            report.failed_tasks.len(),
            report.aborted_tasks.len(),
            deadline.elapsed()
        );

        report
    }

    /// Returns a receiver for mesh task exit events.
    ///
    /// The worker composition root should subscribe before calling `start()`
    /// to avoid missing early critical exits.
    pub fn subscribe_exits(&self) -> broadcast::Receiver<MeshTaskExit> {
        self.mesh_exit_tx.subscribe()
    }

    /// Returns the current lifecycle state.
    pub async fn lifecycle_state(&self) -> MeshLifecycleState {
        *self.lifecycle_state.lock().await
    }

    /// Force-set the lifecycle state for testing.
    ///
    /// Bypasses transition validation to allow integration tests to place the
    /// transport in any state without going through `start_with_policy()`.
    #[cfg(test)]
    pub async fn force_set_lifecycle_state(&self, state: MeshLifecycleState) {
        {
            let mut lock = self.lifecycle_state.lock().await;
            *lock = state;
        }
        self.running_projection.store(
            state == MeshLifecycleState::Running,
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Spawn an auxiliary task via the production path (test-only public wrapper).
    #[cfg(test)]
    pub async fn spawn_auxiliary_task_for_test<F>(
        &self,
        kind: AuxiliaryTaskKind,
        name: &'static str,
        session_id: Option<String>,
        dedup_key: Option<String>,
        future: F,
    ) -> Result<MeshTaskId, crate::lifecycle::SpawnAuxiliaryError>
    where
        F: std::future::Future<Output = MeshTaskExitReason> + Send + 'static,
    {
        self.spawn_auxiliary_task(kind, name, session_id, dedup_key, future)
            .await
    }

    /// Check whether a task ID is present in the auxiliary registry (test-only).
    #[cfg(test)]
    pub async fn has_auxiliary_task(&self, task_id: &MeshTaskId) -> bool {
        self.auxiliary_tasks.lock().await.contains_key(task_id)
    }

    /// Count active auxiliary tasks of a given kind (test-only).
    #[cfg(test)]
    pub async fn count_auxiliary_tasks(&self, kind: AuxiliaryTaskKind) -> usize {
        self.auxiliary_tasks
            .lock()
            .await
            .values()
            .filter(|e| e.kind() == kind)
            .count()
    }

    #[allow(dead_code)]
    pub(crate) async fn bootstrap_from_seeds(
        &self,
        stage: &mut MeshStartupStage,
    ) -> Result<(), MeshTransportError> {
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
            match self.connect_to_peer(&peer_config, Some(stage)).await {
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
        mut stage: Option<&mut MeshStartupStage>,
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
                            crate::cert::MeshCertManager::compute_cert_fingerprint(peer_cert);
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
                            crate::dht::routing::node_id::NodeId::find_pow_nonce(&pk_bytes)
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
                    match crate::peer_auth::generate_global_node_auth(
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
            capabilities: crate::protocol::MeshCapabilities::from_config(
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

        // Capture topology state before mutation (Iteration 73, Phase 2-3)
        // Defined before the match so it survives the HelloAck arm scope.
        let mut topology_snapshot_before: Option<crate::topology::PeerState> = None;

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
                            crate::dht::routing::node_id::NodeId::from_public_key(&pk_bytes);
                        let claimed_node_id =
                            crate::dht::routing::node_id::NodeId::from_node_id_string(
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
                if let Err(e) = crate::peer_auth::validate_peer_role(
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
                    None,
                    false,
                ) {
                    tracing::warn!("Node Ed25519 verification failed for {}: {}", node_id, e);
                    return Err(MeshTransportError::AuthFailed(e));
                }

                let upstreams: Vec<String> = upstreams.keys().cloned().collect();

                let peer_capabilities = peer_capabilities;
                let dns_serving_healthy = peer_capabilities.can_serve_dns;

                self.verify_peer_connection_certificate_if_available(&node_id, &connection)?;

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
                        crate::protocol::ReplayProtection::new(),
                    )),
                    stream_pool: Arc::new(tokio::sync::Mutex::new(MeshStreamPool::new(Some(
                        connection.clone(),
                    )))),
                };

                // Capture topology state before mutation (Iteration 73, Phase 2-3)
                topology_snapshot_before = if stage.is_some() {
                    self.topology.get_peer(&node_id).await
                } else {
                    None
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

        // Capture DHT state before mutation (Iteration 73, Phase 4-6)
        let dht_snapshot_before = if stage.is_some() {
            if let Some(ref rm) = self.routing_manager {
                if rm.is_enabled() {
                    rm.snapshot_peer(&peer_node_id).await
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                if stage.is_some() {
                    self.dht_on_peer_connected_checked(&peer_node_id, &peer_address, peer_role)
                        .await?;
                } else {
                    self.dht_on_peer_connected(&peer_node_id, &peer_address, peer_role)
                        .await;
                }
            }
        }

        // Preflight: query the new peer for their known routes to warm our cache
        //
        // Preflight failure policy: nonfatal, best-effort.
        // - Failure logs only; does not affect startup or connection success.
        // - Task completion is owned (by task group during startup, detached otherwise).
        // - Rollback cancellation is expected during startup.
        // - Route/cache state is not mutated after rollback completion.
        let preflight_node_id = peer_node_id.clone();
        let preflight_transport = self.clone();
        let preflight_future = async move {
            if let Err(e) = preflight_transport
                .preflight_peer_routes(&preflight_node_id)
                .await
            {
                tracing::debug!("Preflight routes from {}: {}", preflight_node_id, e);
            }
        };
        // During startup, preflight is owned by the staged task group for rollback.
        // During steady-state, it runs detached but is tracked in the auxiliary registry.
        if let Some(ref mut startup_stage) = stage {
            startup_stage
                .task_group
                .spawn_child("preflight_peer_routes", preflight_future);
        } else {
            let task_id = self.id_generator.next();
            let session_id_clone = session_id.to_string();
            let aux_exit_tx = self.auxiliary_exit_tx.clone();
            let session_id_for_exit = session_id.to_string();
            let preflight_handle = tokio::spawn(async move {
                preflight_future.await;
                let _ = aux_exit_tx.send(crate::lifecycle::AuxiliaryTaskExit {
                    task_id,
                    session_id: Some(session_id_for_exit),
                    reason: crate::lifecycle::MeshTaskExitReason::CleanCompletion,
                });
                MeshTaskExit {
                    id: task_id,
                    name: "preflight_peer_routes",
                    class: crate::lifecycle::MeshTaskClass::BoundedChild,
                    reason: crate::lifecycle::MeshTaskExitReason::CleanCompletion,
                }
            });
            let mut aux = self.auxiliary_tasks.lock().await;
            aux.insert(
                task_id,
                AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                    task_id,
                    session_id: Some(session_id_clone),
                    kind: AuxiliaryTaskKind::PreflightRoute,
                    handle: preflight_handle,
                    dedup_key: None,
                }),
            );
        }

        // Use transport-global generation for every session (Iteration 74, Phase 25).
        let session_generation_for_task =
            self.session_generation.fetch_add(1, Ordering::SeqCst) + 1;

        let transport = self.clone();
        let conn = connection;
        let topo = self.topology.clone();
        let peer_node_id_for_loop = peer_node_id.clone();
        let session_id_for_loop = session_id.to_string();
        let node_id_for_session = peer_node_id.clone();
        let session_id_key = session_id.to_string();
        let exit_tx = self.session_exit_tx.clone();
        let gen = session_generation_for_task;
        // Cooperative cancellation channel (Iteration 76, Phase 6).
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            let exit = transport
                .peer_message_loop(
                    session_id_for_loop,
                    peer_node_id_for_loop,
                    conn,
                    topo,
                    gen,
                    shutdown_rx,
                )
                .await;
            let _ = exit_tx.send(exit);
        });
        let mut sessions = self.peer_sessions.lock().await;
        sessions.insert(
            session_id_key,
            PeerSessionTask {
                session_id: session_id.to_string(),
                node_id: node_id_for_session,
                handle,
                generation: session_generation_for_task,
                shutdown_tx,
            },
        );

        if let Some(stage) = stage {
            let previous_topology =
                topology_snapshot_before.map(|ps| StagedTopologySnapshot { peer_state: ps });

            // Derive DHT mutation from pre-mutation snapshot
            let dht_mutation = if let Some(ref rm) = self.routing_manager {
                if rm.is_enabled() {
                    match dht_snapshot_before {
                        None => DhtPeerMutation::Created,
                        Some(snapshot) => DhtPeerMutation::Previous(snapshot),
                    }
                } else {
                    DhtPeerMutation::None
                }
            } else {
                DhtPeerMutation::None
            };

            stage.record_peer(StagedPeerResource {
                session_id: session_id.to_string(),
                node_id: peer_info_return.node_id.clone(),
                previous_topology,
                connection_inserted: true,
                session_task_id: Some(session_id.to_string()),
                dht_mutation,
                session_generation: session_generation_for_task,
            });
        }

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
        action: crate::protocol::AnnounceAction,
    ) -> Result<(), MeshTransportError> {
        if !self.topology.can_forward_service(upstream_id) {
            tracing::debug!(
                "Not announcing upstream {} - service not allowed by policy",
                upstream_id
            );
            return Ok(());
        }

        match action {
            crate::protocol::AnnounceAction::Add | crate::protocol::AnnounceAction::Update => {
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
            crate::protocol::AnnounceAction::Remove => {
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
        let block_until_unix = synvoid_utils::safe_unix_timestamp() + blocked_duration_secs;

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
                Some(crate::config::MeshNodeRole::GLOBAL),
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
        evidence: Option<crate::dht::AuditReceipt>,
    ) {
        let block_until_unix = synvoid_utils::safe_unix_timestamp() + blocked_duration_secs;

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
                Some(crate::config::MeshNodeRole::GLOBAL),
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
        role_filter: Option<crate::config::MeshNodeRole>,
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
        role_filter: Option<crate::config::MeshNodeRole>,
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
                    if self.connect_to_peer(&peer_config, None).await.is_ok() {
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

    pub fn get_origin_signer(&self) -> Option<Arc<synvoid_integrity::Ed25519Signer>> {
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

impl crate::dht::routing::manager::FindNodeTransport for MeshTransport {
    fn send_find_node(&self, target: crate::dht::routing::node_id::NodeId, request_id: String) {
        let this = self.clone();
        let node_id = self.config.node_id();
        // Phase 24: Fire-and-forget datagram send — the response arrives
        // asynchronously as a separate datagram routed to pending queries
        // in the DHT layer. The send completes or fails silently; DHT
        // retry logic handles failures via timeout on the pending query.
        tokio::spawn(async move {
            let find_node = MeshMessage::FindNode {
                request_id: request_id.into(),
                target_node_id: target.as_bytes().to_vec(),
                requester_node_id: node_id.into(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
            };
            let _ = this
                .send_datagram_to_peer(&target.to_string(), &find_node)
                .await;
        });
    }
}

impl crate::dht::routing::manager::PingTransport for MeshTransport {
    fn send_ping(&self, node_id: &str, request_id: String, local_node_id: String) {
        let this = self.clone();
        let node_id_owned = node_id.to_string();
        let _node_id = node_id;
        // Phase 24: Fire-and-forget datagram send — same pattern as
        // FindNode. Response arrives as a separate datagram routed to
        // pending queries. DHT retry logic handles failures.
        tokio::spawn(async move {
            let ping = MeshMessage::Ping {
                request_id: request_id.into(),
                node_id: local_node_id.into(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
            };
            let _ = this.send_datagram_to_peer(&node_id_owned, &ping).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        mesh_tls_mode_requires_peer_cert_identity, validate_peer_identity_state_for_mode,
        MeshTlsMode, PeerIdentityState,
    };
    use crate::mesh::cert::MeshCertManager;
    use crate::mesh::config::MeshConfig;
    use crate::mesh::lifecycle::{AuxiliaryTaskKind, MeshLifecycleState, MeshTaskExitReason};
    use crate::mesh::topology::MeshTopology;
    use crate::mesh::transport::MeshTransport;
    use std::sync::Arc;

    #[test]
    fn mesh_tls_mode_requires_identity_for_strict() {
        assert!(mesh_tls_mode_requires_peer_cert_identity(
            MeshTlsMode::Strict
        ));
    }

    #[test]
    fn mesh_tls_mode_requires_identity_for_tofu() {
        assert!(mesh_tls_mode_requires_peer_cert_identity(MeshTlsMode::Tofu));
    }

    #[test]
    fn mesh_tls_mode_allows_missing_identity_for_permissive() {
        assert!(!mesh_tls_mode_requires_peer_cert_identity(
            MeshTlsMode::Permissive
        ));
    }

    #[test]
    fn peer_identity_state_matrix_strict_mode() {
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Strict,
            PeerIdentityState::Missing,
            "peer-a"
        )
        .is_err());
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Strict,
            PeerIdentityState::NotCertificateDer,
            "peer-a"
        )
        .is_err());
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Strict,
            PeerIdentityState::CertificateDer,
            "peer-a"
        )
        .is_ok());
    }

    #[test]
    fn peer_identity_state_matrix_tofu_mode() {
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Tofu,
            PeerIdentityState::Missing,
            "peer-b"
        )
        .is_err());
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Tofu,
            PeerIdentityState::NotCertificateDer,
            "peer-b"
        )
        .is_err());
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Tofu,
            PeerIdentityState::CertificateDer,
            "peer-b"
        )
        .is_ok());
    }

    #[test]
    fn peer_identity_state_matrix_permissive_mode() {
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Permissive,
            PeerIdentityState::Missing,
            "peer-c"
        )
        .is_ok());
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Permissive,
            PeerIdentityState::NotCertificateDer,
            "peer-c"
        )
        .is_ok());
        assert!(validate_peer_identity_state_for_mode(
            MeshTlsMode::Permissive,
            PeerIdentityState::CertificateDer,
            "peer-c"
        )
        .is_ok());
    }

    #[tokio::test]
    async fn stop_peer_session_task_zero_budget_forces_abort() {
        let handle = tokio::spawn(std::future::pending::<()>());
        let outcome =
            super::MeshTransport::stop_peer_session_task(handle, std::time::Duration::ZERO, None)
                .await;

        assert!(
            matches!(outcome, super::PeerSessionStopOutcome::ForcedParentAbort),
            "zero budget should produce ForcedParentAbort, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn stop_peer_session_task_clean_completion_drains() {
        let handle = tokio::spawn(async {});
        let outcome = super::MeshTransport::stop_peer_session_task(
            handle,
            std::time::Duration::from_secs(5),
            None,
        )
        .await;

        assert!(
            matches!(outcome, super::PeerSessionStopOutcome::Drained(_)),
            "clean completion should produce Drained, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn stop_peer_session_task_panic_produces_failed() {
        let handle = tokio::spawn(async {
            panic!("test panic");
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let outcome = super::MeshTransport::stop_peer_session_task(
            handle,
            std::time::Duration::from_secs(5),
            None,
        )
        .await;

        assert!(
            matches!(outcome, super::PeerSessionStopOutcome::Failed(_)),
            "panic should produce Failed, got: {:?}",
            outcome
        );
    }

    // ── Iteration 79, Phase 42: Edge refresh dedup behavioral test ────────

    #[tokio::test]
    async fn dedup_removes_stale_before_capacity_check() {
        use super::*;
        use std::collections::HashMap;

        let mut aux: HashMap<MeshTaskId, AuxiliaryRegistryEntry> = HashMap::new();
        let dedup_key = Some("edge_refresh:ns:key1".to_string());

        // Insert task A with the dedup key.
        let task_id_a = MeshTaskId(1);
        let handle_a = tokio::spawn(async move {
            MeshTaskExit {
                id: MeshTaskId(0),
                name: "test",
                class: crate::lifecycle::MeshTaskClass::BoundedChild,
                reason: MeshTaskExitReason::CleanCompletion,
            }
        });
        aux.insert(
            task_id_a,
            AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                task_id: task_id_a,
                session_id: None,
                kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                handle: handle_a,
                dedup_key: dedup_key.clone(),
            }),
        );
        assert_eq!(aux.len(), 1);

        // Call dedup_and_check_capacity with the same dedup key.
        let stale = MeshTransport::dedup_and_check_capacity(
            &mut aux,
            AuxiliaryTaskKind::EdgeReplicaRefresh,
            &dedup_key,
            8,
        )
        .unwrap();

        // Stale task A should have been removed.
        assert_eq!(stale.len(), 1, "should have removed 1 stale task");
        assert_eq!(stale[0].task_id, task_id_a);
        assert!(!aux.contains_key(&task_id_a), "A must be removed from map");
        assert_eq!(aux.len(), 0, "map should be empty after dedup");

        // Clean up: abort the stale handle.
        for t in stale {
            t.handle.abort();
            let _ = t.handle.await;
        }
    }

    // ── Iteration 79, Phase 43: Edge refresh capacity behavioral test ──────

    #[tokio::test]
    async fn capacity_rejection_at_limit() {
        use super::*;
        use std::collections::HashMap;

        let mut aux: HashMap<MeshTaskId, AuxiliaryRegistryEntry> = HashMap::new();
        let capacity = 3; // use small capacity for test

        // Fill capacity with 3 distinct tasks (no dedup key).
        for i in 0..capacity {
            let task_id = MeshTaskId(i as u64);
            let handle = tokio::spawn(async {
                MeshTaskExit {
                    id: MeshTaskId(0),
                    name: "test",
                    class: crate::lifecycle::MeshTaskClass::BoundedChild,
                    reason: MeshTaskExitReason::CleanCompletion,
                }
            });
            aux.insert(
                task_id,
                AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                    task_id,
                    session_id: None,
                    kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                    handle,
                    dedup_key: None,
                }),
            );
        }
        assert_eq!(aux.len(), capacity);

        // Attempt to insert a 4th task with a distinct dedup key.
        let dedup_key = Some("edge_refresh:ns:new_key".to_string());
        let result = MeshTransport::dedup_and_check_capacity(
            &mut aux,
            AuxiliaryTaskKind::EdgeReplicaRefresh,
            &dedup_key,
            capacity,
        );

        assert!(result.is_err(), "should reject when at capacity");
        assert_eq!(
            aux.len(),
            capacity,
            "map size should not change on rejection"
        );

        // Clean up: abort all handles.
        let entries: Vec<_> = aux.drain().collect();
        for (_id, entry) in entries {
            if let AuxiliaryRegistryEntry::Running(t) = entry {
                t.handle.abort();
                let _ = t.handle.await;
            }
        }
    }

    // ── Iteration 79, Phase 41: Edge refresh normal completion test ────────

    #[tokio::test]
    async fn auxiliary_normal_completion_reaped_without_lag_recovery() {
        use super::*;
        use std::collections::HashMap;

        // Phase 41 requires proving: task completes -> AuxiliaryTaskExit received
        // -> reaper removes registry entry -> active count returns to zero.

        let (exit_tx, _) = tokio::sync::broadcast::channel(16);
        let mut exit_rx = exit_tx.subscribe();

        let task_id = MeshTaskId(77);
        let task_id_for_exit = task_id;
        let aux_exit_tx = exit_tx.clone();

        // Spawn a task that completes normally with CleanCompletion.
        let handle = tokio::spawn(async move {
            let _ = aux_exit_tx.send(AuxiliaryTaskExit {
                task_id: task_id_for_exit,
                session_id: None,
                reason: MeshTaskExitReason::CleanCompletion,
            });
            MeshTaskExit {
                id: task_id_for_exit,
                name: "edge-replica-refresh",
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::CleanCompletion,
            }
        });

        // Register the task in the auxiliary registry.
        let mut aux: HashMap<MeshTaskId, AuxiliaryRegistryEntry> = HashMap::new();
        aux.insert(
            task_id,
            AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                task_id,
                session_id: None,
                kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                handle,
                dedup_key: Some("edge_refresh:ns:normal_key".to_string()),
            }),
        );
        assert_eq!(aux.len(), 1, "registry must have 1 task");

        // Step 1: Receive the AuxiliaryTaskExit event.
        let exit = exit_rx.recv().await.unwrap();
        assert_eq!(exit.task_id, task_id);
        assert!(
            matches!(&exit.reason, MeshTaskExitReason::CleanCompletion),
            "exit must be CleanCompletion, got: {:?}",
            exit.reason
        );

        // Step 2: Reaper removes entry from registry.
        let removed = aux.remove(&exit.task_id);
        assert!(
            removed.is_some(),
            "reaper must remove the task from registry"
        );

        // Step 3: Active count returns to zero.
        assert_eq!(aux.len(), 0, "registry must be empty after reaping");

        // Step 4: Handle must be joinable (no zombie).
        let entry = removed.unwrap();
        let task = match entry {
            AuxiliaryRegistryEntry::Running(t) => t,
            _ => panic!("expected Running entry"),
        };
        let task_exit = task.handle.await.unwrap();
        assert!(
            matches!(&task_exit.reason, MeshTaskExitReason::CleanCompletion),
            "task exit must be CleanCompletion, got: {:?}",
            task_exit.reason
        );
    }

    // ── Iteration 79, Phase 44: Auxiliary failure reason test ──────────────

    #[tokio::test]
    async fn auxiliary_task_failure_carries_error_reason() {
        use super::*;

        let (exit_tx, _) = tokio::sync::broadcast::channel(16);
        let mut exit_rx = exit_tx.subscribe();

        let task_id = MeshTaskId(42);
        let task_id_for_exit = task_id;
        let aux_exit_tx = exit_tx.clone();

        let handle = tokio::spawn(async move {
            let reason = MeshTaskExitReason::Error("leader query failed".to_string());
            let _ = aux_exit_tx.send(AuxiliaryTaskExit {
                task_id: task_id_for_exit,
                session_id: None,
                reason: reason.clone(),
            });
            MeshTaskExit {
                id: task_id_for_exit,
                name: "edge-replica-refresh",
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason,
            }
        });

        // Wait for the task to complete and send its exit event.
        let exit = exit_rx.recv().await.unwrap();
        assert_eq!(exit.task_id, task_id);
        assert!(
            matches!(&exit.reason, MeshTaskExitReason::Error(msg) if msg.contains("leader query failed")),
            "exit reason must carry error, got: {:?}",
            exit.reason
        );

        // The JoinHandle should also carry the error.
        let task_exit = handle.await.unwrap();
        assert!(
            matches!(&task_exit.reason, MeshTaskExitReason::Error(msg) if msg.contains("leader query failed")),
            "task exit must carry error, got: {:?}",
            task_exit.reason
        );
    }

    // ── Iteration 80: Atomic auxiliary task registration tests ──────────────

    #[tokio::test]
    async fn immediate_completion_registry_entry_exists_before_reap() {
        use super::*;
        use std::collections::HashMap;

        let gen = Arc::new(MeshTaskIdGenerator::new());
        let (_exit_tx, _) = broadcast::channel::<crate::lifecycle::AuxiliaryTaskExit>(64);
        let id = gen.next();
        let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            let _ = start_rx.await;
            MeshTaskExit {
                id: MeshTaskId(0),
                name: "test",
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::CleanCompletion,
            }
        });

        let entry = AuxiliaryRegistryEntry::Running(AuxiliaryTask {
            task_id: id,
            session_id: None,
            kind: AuxiliaryTaskKind::Other,
            handle,
            dedup_key: None,
        });

        let mut map = HashMap::new();
        map.insert(id, entry);

        let _ = start_tx.send(());
        assert!(map.contains_key(&id));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(map.contains_key(&id));
    }

    #[tokio::test]
    async fn dedup_removes_stale_matching_key() {
        use super::*;
        use std::collections::HashMap;

        let mut map = HashMap::new();
        let stale_id = MeshTaskId(100);
        let stale_handle = tokio::spawn(async move {
            MeshTaskExit {
                id: stale_id,
                name: "test",
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::CleanCompletion,
            }
        });
        map.insert(
            stale_id,
            AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                task_id: stale_id,
                session_id: None,
                kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                handle: stale_handle,
                dedup_key: Some("edge_refresh:ns:key1".to_string()),
            }),
        );

        let stale = MeshTransport::dedup_and_check_capacity(
            &mut map,
            AuxiliaryTaskKind::EdgeReplicaRefresh,
            &Some("edge_refresh:ns:key1".to_string()),
            8,
        )
        .unwrap();

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].task_id, stale_id);
        assert!(!map.contains_key(&stale_id));
    }

    #[tokio::test]
    async fn capacity_rejection_returns_error() {
        use super::*;
        use std::collections::HashMap;

        let mut map = HashMap::new();

        for i in 0..8 {
            let id = MeshTaskId(i);
            let handle = tokio::spawn(async {
                MeshTaskExit {
                    id: MeshTaskId(0),
                    name: "test",
                    class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                    reason: MeshTaskExitReason::CleanCompletion,
                }
            });
            map.insert(
                id,
                AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                    task_id: id,
                    session_id: None,
                    kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                    handle,
                    dedup_key: None,
                }),
            );
        }

        let result = MeshTransport::dedup_and_check_capacity(
            &mut map,
            AuxiliaryTaskKind::EdgeReplicaRefresh,
            &None,
            8,
        );
        assert!(result.is_err());
    }

    // ── Iteration 80: Barrier-based concurrent race tests ─────────────────

    /// Prove the gated-start pattern prevents completion before registration.
    ///
    /// Uses a barrier to force the future to wait while the registry is checked,
    /// proving that completion cannot race ahead of registration insertion.
    #[tokio::test]
    async fn concurrent_gate_prevents_early_completion() {
        use super::*;
        use std::collections::HashMap;

        let gen = Arc::new(MeshTaskIdGenerator::new());
        let (_exit_tx, _) = broadcast::channel::<crate::lifecycle::AuxiliaryTaskExit>(64);
        let id = gen.next();

        // Barrier: future waits here until main thread confirms registry state.
        let gate = Arc::new(tokio::sync::Barrier::new(2));
        let gate_clone = gate.clone();

        let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            // Wait for the gate signal (main thread will check registry first).
            let _ = start_rx.await;
            // Now wait on the barrier — this proves the future is still alive
            // and hasn't completed yet when main checks the registry.
            gate_clone.wait().await;
            MeshTaskExit {
                id: MeshTaskId(0),
                name: "test",
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::CleanCompletion,
            }
        });

        // Register the task in the map.
        let mut map = HashMap::new();
        map.insert(
            id,
            AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                task_id: id,
                session_id: None,
                kind: AuxiliaryTaskKind::Other,
                handle,
                dedup_key: None,
            }),
        );

        // Open the gate — future starts but blocks on the barrier.
        let _ = start_tx.send(());

        // The future is running but blocked on the barrier.
        // Prove registry has the entry while the future is still running.
        assert!(
            map.contains_key(&id),
            "registry must contain entry while future is gated"
        );

        // Release the barrier so the future can complete.
        gate.wait().await;

        // Now wait for the future to finish.
        let entry = map.remove(&id).unwrap();
        if let AuxiliaryRegistryEntry::Running(task) = entry {
            let exit = task.handle.await.unwrap();
            assert!(matches!(exit.reason, MeshTaskExitReason::CleanCompletion));
        } else {
            panic!("expected Running entry");
        }
        assert!(map.is_empty());
    }

    /// Two concurrent submissions with the same dedup key must result in at
    /// most one active entry after both complete.
    ///
    /// Uses a `tokio::sync::Mutex` to share the map across concurrent tasks,
    /// then verifies the dedup function correctly handles overlapping calls.
    #[tokio::test]
    async fn concurrent_duplicate_submissions_at_most_one_running() {
        use super::*;
        use std::collections::HashMap;
        use std::sync::Arc;

        let dedup_key = Some("edge_refresh:ns:race_key".to_string());
        let capacity = 8;

        // Pre-populate the map with a "stale" entry sharing the same dedup key.
        let mut map = HashMap::new();
        let stale_id = MeshTaskId(100);
        let stale_handle = tokio::spawn(async {
            MeshTaskExit {
                id: MeshTaskId(100),
                name: "stale",
                class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::CleanCompletion,
            }
        });
        map.insert(
            stale_id,
            AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                task_id: stale_id,
                session_id: None,
                kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                handle: stale_handle,
                dedup_key: dedup_key.clone(),
            }),
        );

        let map = Arc::new(tokio::sync::Mutex::new(map));

        // Two concurrent dedup+capacity checks with the same dedup key.
        let (r1, r2) = tokio::join!(
            async {
                let mut map = map.lock().await;
                MeshTransport::dedup_and_check_capacity(
                    &mut map,
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    &dedup_key,
                    capacity,
                )
            },
            async {
                let mut map = map.lock().await;
                MeshTransport::dedup_and_check_capacity(
                    &mut map,
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    &dedup_key,
                    capacity,
                )
            }
        );

        // At least one must have removed the stale entry.
        let stale1 = r1.unwrap();
        let stale2 = r2.unwrap();
        let total_stale = stale1.len() + stale2.len();
        assert!(
            total_stale >= 1,
            "at least one call must remove the stale entry"
        );

        // The map must not contain the stale entry anymore.
        let map = map.lock().await;
        assert!(
            !map.contains_key(&stale_id),
            "stale entry must be removed from map"
        );
    }

    /// Concurrent submissions that exceed capacity must never allow more than
    /// the configured limit to be active in the registry.
    ///
    /// Uses a `tokio::sync::Mutex` to share the map across concurrent tasks,
    /// simulating the real `spawn_auxiliary_task` flow under the submission lock.
    #[tokio::test]
    async fn concurrent_capacity_boundary_never_exceeded() {
        use super::*;
        use std::collections::HashMap;
        use std::sync::Arc;

        let capacity: usize = 3;
        let extras: usize = 5;

        // Fill the map to capacity.
        let mut map = HashMap::new();
        for i in 0..capacity {
            let id = MeshTaskId(i as u64);
            let handle = tokio::spawn(async {
                MeshTaskExit {
                    id: MeshTaskId(0),
                    name: "test",
                    class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                    reason: MeshTaskExitReason::CleanCompletion,
                }
            });
            map.insert(
                id,
                AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                    task_id: id,
                    session_id: None,
                    kind: AuxiliaryTaskKind::EdgeReplicaRefresh,
                    handle,
                    dedup_key: None,
                }),
            );
        }

        let map = Arc::new(tokio::sync::Mutex::new(map));

        // Spawn `extras` concurrent capacity checks, each with a unique dedup key.
        let mut handles = Vec::new();
        for j in 0..extras {
            let map = map.clone();
            let dedup_key = Some(format!("edge_refresh:ns:extra_{}", j));
            let handle = tokio::spawn(async move {
                // Small delay to create overlap between tasks.
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;

                let mut map = map.lock().await;
                MeshTransport::dedup_and_check_capacity(
                    &mut map,
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    &dedup_key,
                    capacity,
                )
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Count successes vs rejections.
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let rejections = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(
            successes + rejections,
            extras,
            "every submission must resolve"
        );
        assert!(
            rejections > 0,
            "some submissions must be rejected when at capacity"
        );
        assert!(successes <= extras - 1, "not all extras can succeed");

        // Verify map never exceeds capacity.
        let map = map.lock().await;
        let active = map
            .values()
            .filter(|e| e.kind() == AuxiliaryTaskKind::EdgeReplicaRefresh)
            .count();
        assert!(
            active <= capacity,
            "registry active count {} must not exceed capacity {}",
            active,
            capacity
        );
    }

    /// When start_tx is dropped (simulating shutdown/cancellation), the gated
    /// task must exit cleanly without executing the user future.
    #[tokio::test]
    async fn shutdown_during_reservation_cleans_up() {
        use super::*;
        use std::collections::HashMap;

        let gen = Arc::new(MeshTaskIdGenerator::new());
        let (exit_tx, _) = broadcast::channel::<crate::lifecycle::AuxiliaryTaskExit>(64);
        let mut exit_rx = exit_tx.subscribe();
        let id = gen.next();
        let aux_exit_tx = exit_tx.clone();
        let task_id_for_exit = id;

        // Spawn a future that waits for the gate, then waits forever
        // (proving it never executes the user body).
        let handle = tokio::spawn(async move {
            // Simulate the gated-start pattern: wait for start_rx.
            let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
            // Immediately drop start_tx to simulate shutdown/cancellation.
            drop(start_tx);

            if start_rx.await.is_err() {
                // Gate dropped — publish exit and return cancelled.
                let reason = MeshTaskExitReason::Cancelled;
                let _ = aux_exit_tx.send(crate::lifecycle::AuxiliaryTaskExit {
                    task_id: task_id_for_exit,
                    session_id: None,
                    reason: reason.clone(),
                });
                return MeshTaskExit {
                    id: task_id_for_exit,
                    name: "gated-shutdown",
                    class: crate::lifecycle::MeshTaskClass::RestartableBackground,
                    reason,
                };
            }
            // Should never reach here.
            panic!("user future executed after gate drop");
        });

        // Register the task.
        let mut map = HashMap::new();
        map.insert(
            id,
            AuxiliaryRegistryEntry::Running(AuxiliaryTask {
                task_id: id,
                session_id: None,
                kind: AuxiliaryTaskKind::Other,
                handle,
                dedup_key: None,
            }),
        );

        // The gate is already dropped inside the task, so it should exit.
        // Wait for the exit event.
        let exit = tokio::time::timeout(std::time::Duration::from_secs(5), exit_rx.recv())
            .await
            .expect("timeout waiting for exit event")
            .expect("exit channel closed");

        assert_eq!(exit.task_id, id);
        assert!(matches!(exit.reason, MeshTaskExitReason::Cancelled));

        // Reaper removes the entry.
        let removed = map.remove(&exit.task_id);
        assert!(removed.is_some(), "reaper must remove cancelled entry");

        // Handle must be joinable.
        let entry = removed.unwrap();
        if let AuxiliaryRegistryEntry::Running(task) = entry {
            let task_exit = task.handle.await.unwrap();
            assert!(matches!(task_exit.reason, MeshTaskExitReason::Cancelled));
        }
        assert!(map.is_empty());
    }

    // ── Phase 22: Production-Path Auxiliary Race Tests ──────────────────
    //
    // Exercise spawn_auxiliary_task on a real MeshTransport instance.

    fn make_test_transport_for_aux() -> Arc<MeshTransport> {
        let config = Arc::new(MeshConfig::default());
        let topology = Arc::new(MeshTopology::new(config.clone()));
        let cert_manager = Arc::new(parking_lot::RwLock::new(MeshCertManager::new(&config)));
        Arc::new(MeshTransport::new(
            config,
            topology,
            cert_manager,
            None,
            None,
            None,
            None,
            None,
            None,
            #[cfg(feature = "dns")]
            None,
            #[cfg(feature = "dns")]
            None,
        ))
    }

    #[tokio::test]
    async fn aux_submission_rejected_when_stopped() {
        let transport = make_test_transport_for_aux();
        let result = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-stopped",
                None,
                Some("key:1".into()),
                async { MeshTaskExitReason::CleanCompletion },
            )
            .await;
        assert!(result.is_err(), "submission must be rejected when Stopped");
    }

    #[tokio::test]
    async fn aux_immediate_completion_through_production_path() {
        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        let task_id = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-immediate",
                None,
                Some("immediate:1".into()),
                async { MeshTaskExitReason::CleanCompletion },
            )
            .await
            .expect("submission must succeed in Running state");

        // Registry entry is installed before the future executes (gate pattern).
        assert!(
            transport.has_auxiliary_task(&task_id).await,
            "registry must contain the task after successful submission"
        );
    }

    #[tokio::test]
    async fn aux_concurrent_duplicate_submissions_dedup() {
        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        let dedup_key = Some("edge_refresh:ns:dup_key".into());

        let id1 = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-dup1",
                None,
                dedup_key.clone(),
                async {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    MeshTaskExitReason::CleanCompletion
                },
            )
            .await
            .expect("first submission must succeed");

        let id2 = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-dup2",
                None,
                dedup_key.clone(),
                async {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    MeshTaskExitReason::CleanCompletion
                },
            )
            .await
            .expect("second submission (dedup) must succeed");

        assert_ne!(id1, id2, "task IDs must differ");

        // First task must have been aborted (stale dedup).
        assert!(
            !transport.has_auxiliary_task(&id1).await,
            "stale dedup entry must be removed"
        );
        assert!(
            transport.has_auxiliary_task(&id2).await,
            "new dedup entry must remain"
        );
    }

    #[tokio::test]
    async fn aux_capacity_boundary_never_exceeded() {
        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        // MAX_CONCURRENT_EDGE_REPLICA_REFRESH = 8.
        for i in 0..9 {
            let key = Some(format!("edge_refresh:ns:cap_{i}"));
            let _result = transport
                .spawn_auxiliary_task(
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    "test-cap",
                    None,
                    key,
                    async {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        MeshTaskExitReason::CleanCompletion
                    },
                )
                .await;
        }

        let active = transport
            .count_auxiliary_tasks(AuxiliaryTaskKind::EdgeReplicaRefresh)
            .await;
        assert!(active <= 8, "registry must not exceed capacity: {active}");
    }

    #[tokio::test]
    async fn aux_shutdown_rejects_new_submissions() {
        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        // Begin shutdown — sets lifecycle to Stopping.
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Stopping)
            .await;

        let result = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-shutdown",
                None,
                Some("shutdown:1".into()),
                async { MeshTaskExitReason::CleanCompletion },
            )
            .await;
        assert!(
            result.is_err(),
            "submission must be rejected after shutdown begins"
        );
    }

    #[tokio::test]
    async fn aux_rejected_future_does_not_execute() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let transport = make_test_transport_for_aux();
        // Transport is Stopped — submission will be rejected.

        let executed = Arc::new(AtomicBool::new(false));
        let executed_clone = executed.clone();

        let _result = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-no-exec",
                None,
                Some("noexec:1".into()),
                async move {
                    executed_clone.store(true, Ordering::SeqCst);
                    MeshTaskExitReason::CleanCompletion
                },
            )
            .await;

        // Give the gated task time to process the cancellation.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert!(
            !executed.load(Ordering::SeqCst),
            "rejected future must not execute its body"
        );
    }

    #[tokio::test]
    async fn aux_failed_state_rejects_submissions() {
        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Failed)
            .await;

        let result = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-failed",
                None,
                Some("failed:1".into()),
                async { MeshTaskExitReason::CleanCompletion },
            )
            .await;
        assert!(result.is_err(), "submission must be rejected when Failed");
    }

    // ── Phase 22: True Concurrent Race Tests ─────────────────────────────
    //
    // These tests exercise actual concurrency between submission and
    // shutdown/recovery, verifying the submission lock prevents races.

    #[tokio::test]
    async fn aux_shutdown_races_with_active_submission() {
        use std::sync::Arc;

        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        // Submit a long-running task so the registry is non-empty.
        let task_id = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-race-shutdown",
                None,
                Some("race-shutdown:1".into()),
                async {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    MeshTaskExitReason::CleanCompletion
                },
            )
            .await
            .expect("initial submission must succeed");
        assert!(
            transport.has_auxiliary_task(&task_id).await,
            "registry must contain the task"
        );

        // Spawn a concurrent submission attempt.
        let transport_clone = Arc::clone(&transport);
        let submission_handle = tokio::spawn(async move {
            transport_clone
                .spawn_auxiliary_task(
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    "test-race-concurrent",
                    None,
                    Some("race-concurrent:1".into()),
                    async {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        MeshTaskExitReason::CleanCompletion
                    },
                )
                .await
        });

        // Begin shutdown — drains auxiliary tasks under the submission lock.
        transport
            .shutdown_with_timeout(std::time::Duration::from_secs(10))
            .await;

        // The concurrent submission must have completed (either accepted or rejected).
        let submission_result = submission_handle
            .await
            .expect("submission task must complete");

        // Regardless of which won the race, the registry must be empty.
        assert_eq!(
            transport
                .count_auxiliary_tasks(AuxiliaryTaskKind::EdgeReplicaRefresh)
                .await,
            0,
            "shutdown must drain all auxiliary tasks"
        );

        // If the submission was accepted, its handle must have been aborted by shutdown.
        if let Ok(submitted_id) = submission_result {
            assert!(
                !transport.has_auxiliary_task(&submitted_id).await,
                "shutdown-drained entry must not remain in registry"
            );
        }
    }

    #[tokio::test]
    async fn aux_recovery_drains_during_submission() {
        use std::sync::Arc;

        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        // Submit a long-running task.
        let task_id = transport
            .spawn_auxiliary_task(
                AuxiliaryTaskKind::EdgeReplicaRefresh,
                "test-race-recovery",
                None,
                Some("race-recovery:1".into()),
                async {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    MeshTaskExitReason::CleanCompletion
                },
            )
            .await
            .expect("initial submission must succeed");

        // Simulate transport entering Failed state.
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Failed)
            .await;

        // Spawn recovery — will acquire submission lock and drain tasks.
        let transport_clone = Arc::clone(&transport);
        let recovery_handle = tokio::spawn(async move {
            transport_clone
                .recover_failed_state(std::time::Duration::from_secs(10))
                .await
        });

        // Spawn a concurrent submission attempt that races with recovery.
        let transport_clone2 = Arc::clone(&transport);
        let submission_handle = tokio::spawn(async move {
            transport_clone2
                .spawn_auxiliary_task(
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    "test-race-recovery-submission",
                    None,
                    Some("race-recovery-sub:1".into()),
                    async {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        MeshTaskExitReason::CleanCompletion
                    },
                )
                .await
        });

        // Wait for both to complete.
        let (recovery_result, submission_result) = tokio::join!(recovery_handle, submission_handle);
        let _recovery_result = recovery_result.expect("recovery task must not panic");
        let submission_result = submission_result.expect("submission task must complete");

        // After recovery, registry must be empty (all tasks drained).
        assert_eq!(
            transport
                .count_auxiliary_tasks(AuxiliaryTaskKind::EdgeReplicaRefresh)
                .await,
            0,
            "recovery must drain all auxiliary tasks"
        );

        // Recovery must have transitioned to Stopped.
        assert_eq!(
            transport.lifecycle_state().await,
            crate::lifecycle::MeshLifecycleState::Stopped,
            "recovery must transition to Stopped"
        );

        // The submission was either rejected (Failed state) or accepted and drained.
        if let Ok(submitted_id) = submission_result {
            assert!(
                !transport.has_auxiliary_task(&submitted_id).await,
                "recovery-drained entry must not remain in registry"
            );
        }
    }

    #[tokio::test]
    async fn aux_full_lifecycle_cleanup() {
        // Criterion 14: verify that all auxiliary resources are cleaned up
        // after a full submit-shutdown lifecycle.
        let transport = make_test_transport_for_aux();
        transport
            .force_set_lifecycle_state(crate::lifecycle::MeshLifecycleState::Running)
            .await;

        // Submit multiple tasks of different kinds.
        let mut ids = Vec::new();
        for i in 0..4 {
            let id = transport
                .spawn_auxiliary_task(
                    AuxiliaryTaskKind::EdgeReplicaRefresh,
                    "test-cleanup",
                    None,
                    Some(format!("cleanup:{i}")),
                    async {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        MeshTaskExitReason::CleanCompletion
                    },
                )
                .await
                .expect("submission must succeed");
            ids.push(id);
        }

        // Verify all tasks are registered.
        let active = transport
            .count_auxiliary_tasks(AuxiliaryTaskKind::EdgeReplicaRefresh)
            .await;
        assert_eq!(active, 4, "must have 4 active auxiliary tasks");

        // Shutdown drains everything.
        transport
            .shutdown_with_timeout(std::time::Duration::from_secs(10))
            .await;

        // Verify: registry empty, all handles cleaned up, lifecycle in Stopped.
        let remaining = transport
            .count_auxiliary_tasks(AuxiliaryTaskKind::EdgeReplicaRefresh)
            .await;
        assert_eq!(remaining, 0, "shutdown must drain all auxiliary tasks");

        for id in &ids {
            assert!(
                !transport.has_auxiliary_task(id).await,
                "task {id:?} must not remain after shutdown"
            );
        }

        assert_eq!(
            transport.lifecycle_state().await,
            crate::lifecycle::MeshLifecycleState::Stopped,
            "lifecycle must be Stopped after shutdown"
        );
    }
}
