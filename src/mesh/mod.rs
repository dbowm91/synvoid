//! Mesh networking subsystem for MaluWAF.
//!
//! Provides peer-to-peer connectivity, DHT-based service discovery,
//! encrypted transport (QUIC, WireGuard), multi-tenant organization
//! management, and distributed DNS with DNSSEC support.

pub mod audit;
pub mod audit_session;
pub mod backend;
pub mod cert;
pub mod cert_dist;
pub mod cli;
pub mod client_audit;
pub mod config;
pub mod dht;
pub mod global_node_ha;
pub mod hierarchical_routing;
pub mod kem;
pub mod ml_kem_key_exchange;
pub mod network_security;
pub mod organization;
pub mod passover_key_exchange;
pub mod peer_auth;
pub mod protocol;
pub mod proxy;
pub mod reputation;
pub mod security;
pub mod security_challenge;
pub mod session;
pub mod threat_intel;
pub mod tier_key_encryption;
pub mod topology;
pub mod transport;
#[cfg(feature = "mesh")]
pub mod transport_connection;
pub mod transport_core;
#[cfg(feature = "mesh")]
pub mod transport_dht;
#[cfg(feature = "mesh")]
pub mod transport_dns;
#[cfg(feature = "mesh")]
pub mod transport_global;
#[cfg(feature = "mesh")]
pub mod transport_org;
#[cfg(feature = "mesh")]
pub mod transport_peer;
#[cfg(feature = "mesh")]
pub mod transport_rate_limit;
#[cfg(feature = "mesh")]
pub mod transport_routing;
pub mod transport_types;
pub mod transports;
pub mod verification;
pub mod wasm_dist;
pub mod yara_rules;

pub use crate::utils::{safe_unix_duration, safe_unix_timestamp};

pub use audit::{
    AuditEvent, AuditEventType, AuditLogger, AuditResult, AuditSeverity, AuditSource, AuditTarget,
};
pub use audit_session::{AuditSession, AuditSessionManager, SessionValidationResult};
pub use backend::{
    create_mesh_backend_from_config, initialize_mesh_transports, MeshBackend, MeshBackendPool,
};
pub use cert::MeshCertManager;
pub use cli::{MeshArgs, MeshCommand};
pub use client_audit::{
    handle_audit_report, AuditReportResponse, AuditResults, AuditSummary, ClientAuditManager,
    ClientAuditReport, NodeProbeResult,
};
pub use config::{
    MeshConfig, MeshMlKemConfig, MeshNodeRole, MeshTransportPreference, MeshWireGuardConfig,
    MeshWireGuardPeer, NodeIdentityConfig,
};
pub use dht::{
    DhtAccessControl, DhtConfig, DhtError, DhtKey, DhtRecordEntry, MerkleNode, MerkleProof,
    MerkleProofNode, MerkleTree, NodeInfo, ProofPosition, RecordStoreConfig, RecordStoreManager,
    RecordStoreStats, TierKeyStore, TierKeyStoreEntry,
};
pub use global_node_ha::{
    GlobalNodeHAConfig, GlobalNodeHAManager, GlobalNodeLeaderTracker, GlobalNodeRole,
    GlobalNodeState, HeartbeatMessage, LeaderInfo, VoteRequest, VoteResponse,
};
pub use hierarchical_routing::{
    DirectedRouteQuery, HierarchicalRoutingConfig, HierarchicalRoutingManager, MeshBloomFilter,
    RegionalHubInfo, RouteAdvertisement,
};
pub use kem::{KemSession, MlKem768, MlKem768PublicKey, MlKem768SecretKey, MlKem768SharedSecret};
pub use ml_kem_key_exchange::MlKemKeyExchangeService;
pub use network_security::{
    AccessAction, AccessDecision, ConnectionState, MeshDataEncryption, NetworkAccessControl,
    NetworkAccessRule, Protocol, TrafficDirection,
};
pub use organization::{
    is_mesh_name_allowed, is_org_name_allowed, sanitize_mesh_name, sanitize_mesh_name_with_config,
    sanitize_org_name, sanitize_org_name_with_config, MemberCertificate, NameValidationError,
    OrgKey, Organization, OrganizationManager, TierClaim, TierKey, TierKeyAnnounce, TierKeyQuery,
    TierKeyQueryResponse, TierKeyRevoke, UnspentTierKeyAnnounce, ADMIN_ORG_ID, GENESIS_ORG_ID,
};
pub use passover_key_exchange::KeyExchangeService;
pub use protocol::{MeshMessage, MessageCategory, ServerlessFunctionAnnounce};
pub use proxy::MeshProxy;
pub use reputation::{
    PeerReputation, PeerReputationStats, ReputationConfig, ReputationEventType, ReputationManager,
    ThreatAcceptanceDecision,
};
pub use security::{
    ConfigSecurityIssue, EncryptedConfig, SecureConfigError, SecureConfigManager,
    SecureConfigValue, SecurityEvent, SecurityEventLogger, SecurityEventType, SecuritySeverity,
};
pub use security_challenge::{
    AttackEvent, AttackSeverity, ChallengeType, MeshAttackDetector, MeshSecurityChallenge,
    MeshSecurityChallengeManager, PatternType, SuspiciousPattern,
};
pub use session::{Session, SessionConfig, SessionError, SessionManager};
pub use threat_intel::{
    ThreatIndicatorEntry, ThreatIntelligenceConfig, ThreatIntelligenceManager,
    ThreatIntelligenceStats,
};
pub use tier_key_encryption::{
    deserialize_encrypted_tier_key, serialize_encrypted_tier_key, EncryptedTierKeyData,
    TierKeyEncryption, TierKeyEncryptionError,
};
pub use topology::{MeshTopology, NetworkPartitionState, PeerState};
pub use transport::{MeshPeerConnection, MeshTransport};
pub use transport_core::{
    get_time_validation_error_count, validate_system_time, MeshTransportError,
    MAX_REASONABLE_TIMESTAMP, MIN_REASONABLE_TIMESTAMP,
};
pub use transports::{
    DatagramPacket, MeshDatagramHandler, MeshPeerConnectionTrait, MeshTransportManager,
    MeshTransportTrait, MeshTransportType, QuicMeshTransport,
};
pub use wasm_dist::{
    get_global_wasm_dist_manager, set_global_wasm_dist_manager, WasmDistManager, WasmModuleStore,
    WasmStoreError,
};
pub use yara_rules::{
    YaraRuleSource, YaraRuleSubmission, YaraRuleSubmissionStatus, YaraRuleVersionInfo,
    YaraRulesManager, YaraRulesStats,
};
