//! Raft consensus module for MaluWAF Global Control Plane
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

pub mod network;
pub mod state_machine;

pub use network::MeshRaftNetwork;
pub use network::MeshRaftNetworkFactory;
pub use state_machine::{
    GlobalRegistry, GlobalRegistryConfig, GlobalRegistryLogStorage,
    GlobalRegistryStateMachine,
    Namespace, OrgPublicKey, ThreatIntel, GlobalNodeRevocationList,
    StateMachineValue, RaftCommand,
};