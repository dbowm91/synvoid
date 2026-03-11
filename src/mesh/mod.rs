pub mod config;
pub mod protocol;
pub mod topology;
pub mod proxy;
pub mod cert;
pub mod backend;
pub mod transport;
pub mod security;
pub mod audit;
pub mod security_challenge;
pub mod network_security;
pub mod wireguard_mesh;
pub mod transports;
pub mod cli;
pub mod reputation;
pub mod threat_intel;
pub mod organization;
pub mod dht;
pub mod passover_key_exchange;
pub mod client_audit;
pub mod audit_session;
pub mod yara_rules;
pub mod kem;
pub mod session;
pub mod ml_kem_key_exchange;

pub use config::{MeshConfig, MeshNodeRole, MeshWireGuardConfig, MeshWireGuardPeer, MeshTransportPreference, NodeIdentityConfig, MeshMlKemConfig};
pub use protocol::MeshMessage;
pub use topology::{MeshTopology, PeerState, NetworkPartitionState};
pub use proxy::MeshProxy;
pub use cert::MeshCertManager;
pub use backend::{MeshBackend, MeshBackendPool, create_mesh_backend_from_config, initialize_mesh_transports};
pub use passover_key_exchange::KeyExchangeService;
pub use transport::{MeshTransport, MeshPeerConnection};
pub use transport::MeshTransportError as MeshTransportErrorV1;
pub use transports::{
    MeshTransportTrait, MeshTransportType, MeshPeerConnectionTrait,
    MeshTransportError, DatagramPacket, MeshDatagramHandler,
    QuicMeshTransport,
    WireGuardMeshTransport,
    MeshTransportManager,
};
pub use security::{
    SecureConfigManager, SecureConfigError, SecureConfigValue, EncryptedConfig,
    SecurityEventLogger, SecurityEvent, SecurityEventType, SecuritySeverity, ConfigSecurityIssue,
};
pub use audit::{
    AuditLogger, AuditEvent, AuditEventType, AuditSource, AuditTarget, AuditResult, AuditSeverity,
};
pub use client_audit::{
    ClientAuditManager, ClientAuditReport, AuditResults, NodeProbeResult, AuditSummary,
    AuditReportResponse, handle_audit_report,
};
pub use audit_session::{
    AuditSessionManager, AuditSession, SessionValidationResult,
};
pub use security_challenge::{
    MeshSecurityChallengeManager, MeshSecurityChallenge, ChallengeType,
    MeshAttackDetector, SuspiciousPattern, PatternType, AttackSeverity, AttackEvent,
};
pub use network_security::{
    NetworkAccessControl, NetworkAccessRule, AccessAction, TrafficDirection, Protocol, AccessDecision,
    ConnectionState, MeshDataEncryption,
};
pub use reputation::{
    ReputationManager, ReputationConfig, PeerReputation, PeerReputationStats,
    ThreatAcceptanceDecision, ReputationEventType,
};
pub use threat_intel::{
    ThreatIntelligenceManager, ThreatIntelligenceConfig, ThreatIntelligenceStats,
    ThreatIndicatorEntry,
};
pub use organization::{
    Organization, OrganizationManager, TierKey, TierClaim,
    TierKeyAnnounce, TierKeyRevoke, TierKeyQuery, TierKeyQueryResponse,
    UnspentTierKeyAnnounce,
    OrgKey, MemberCertificate,
    sanitize_org_name, sanitize_mesh_name, sanitize_org_name_with_config, sanitize_mesh_name_with_config,
    is_org_name_allowed, is_mesh_name_allowed,
    NameValidationError,
    GENESIS_ORG_ID, ADMIN_ORG_ID,
};
pub use cli::{MeshArgs, MeshCommand};
pub use dht::{
    DhtConfig, DhtError, DhtKey, DhtAccessControl,
    NodeInfo,
    RecordStoreManager, RecordStoreConfig, RecordStoreStats, DhtRecordEntry,
    TierKeyStore, TierKeyStoreEntry,
    MerkleTree, MerkleProof, MerkleNode, MerkleProofNode, ProofPosition,
};
pub use yara_rules::{
    YaraRulesManager, YaraRuleSubmission, YaraRuleSubmissionStatus,
    YaraRuleVersionInfo, YaraRuleSource, YaraRulesStats,
};
pub use kem::{KemSession, MlKem768, MlKem768PublicKey, MlKem768SecretKey, MlKem768SharedSecret};
pub use session::{Session, SessionConfig, SessionError, SessionManager};
pub use ml_kem_key_exchange::MlKemKeyExchangeService;
