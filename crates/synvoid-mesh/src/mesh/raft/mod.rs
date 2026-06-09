//! Raft consensus module for SynVoid Global Control Plane
//!
//! This module provides Raft integration for the Global Node tier,
//! enabling strong consistency for OrgPublicKey and ThreatIntel records.
//!
//! # Architecture
//!
//! - `network.rs` - RaftNetworkFactory implementation wrapping MeshBackendPool
//!
//! # Usage
//!
//! Global nodes form a Raft cluster for consensus on:
//! - Namespace::Org: OrgPublicKey records
//! - Namespace::Intel: ThreatIntel indicators
//! - Namespace::Revocation: GlobalNodeRevocationList
//!
//! Edge and Origin nodes use ConsistentRead RPC to query the cluster.

pub mod client;
pub mod consensus;
pub mod edge_replica;
pub mod instance;
pub mod network;
pub mod state_machine;

#[cfg(test)]
pub mod regression_tests;

pub use client::{
    ConsistentReadResult, ConsistentReadSource, RaftAwareClient, RaftAwareClientError,
};
pub use consensus::{ConsensusTransport, MeshConsensusTransportAdapter, RecordReader};
pub use edge_replica::{
    create_edge_replica_manager, create_edge_replica_manager_with_freshness, EdgeReplicaManager,
    FreshnessCheckResult, StaleAuthorityMetrics,
};
pub use instance::{RaftInitConfig, RaftInstance, RaftSnapshotManager};
pub use network::MeshRaftNetwork;
pub use network::MeshRaftNetworkFactory;
pub use state_machine::{
    GlobalNodeRevocationList, GlobalRegistry, GlobalRegistryConfig, GlobalRegistryLogStorage,
    GlobalRegistryStateMachine, Namespace, NodeId, OrgPublicKey, RaftCommand, StateMachineValue,
    ThreatIntel,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaftCommitNotification {
    pub leader_id: String,
    pub commit_index: u64,
    pub namespace: state_machine::Namespace,
    pub key_id: String,
    pub timestamp: u64,
}

impl RaftCommitNotification {
    pub fn new(
        leader_id: String,
        commit_index: u64,
        namespace: state_machine::Namespace,
        key_id: String,
    ) -> Self {
        Self {
            leader_id,
            commit_index,
            namespace,
            key_id,
            timestamp: synvoid_utils::safe_unix_timestamp(),
        }
    }
}
