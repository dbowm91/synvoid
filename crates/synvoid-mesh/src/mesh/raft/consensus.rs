//! Consensus transport abstraction layer.
//!
//! This module defines traits that decouple Raft consensus logic from
//! concrete mesh transport and DHT storage implementations. The goal
//! is to make the internal boundary between consensus and transport
//! real, so that a future `synvoid-consensus` crate extraction is possible
//! without pulling in mesh-specific types.
//!
//! # Design Principles
//!
//! - **ConsensusTransport**: Abstracts the wire-level send path. Raft
//!   sends RPCs through this trait rather than calling `MeshTransport` directly.
//! - **RecordReader**: Abstracts stale-read fallback. The Raft client can
//!   read from a local DHT cache without depending on `RecordStoreManager`.
//! - Peer health is a transport-provided signal; consensus does not own
//!   discovery logic.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::protocol::MeshMessage;

/// Errors that can occur during consensus transport operations.
#[derive(Debug)]
pub enum ConsensusTransportError {
    /// The target peer is not connected or not found.
    PeerNotFound(String),
    /// The send operation failed (network error, timeout, etc.).
    SendFailed(String),
    /// No transport is available.
    NoTransport,
}

impl fmt::Display for ConsensusTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerNotFound(id) => write!(f, "peer not found: {}", id),
            Self::SendFailed(msg) => write!(f, "send failed: {}", msg),
            Self::NoTransport => write!(f, "no transport available"),
        }
    }
}

impl std::error::Error for ConsensusTransportError {}

/// Abstraction over the mesh transport layer used by Raft consensus.
///
/// This trait narrows the interface that Raft needs from the transport,
/// removing direct dependencies on `MeshProxy`, `MeshBackendPool`, and
/// `MeshTransport` concrete types from the consensus code path.
///
/// # Implementors
///
/// Any transport that can send `MeshMessage` to a peer by string ID
/// qualifies. The primary implementation wraps `MeshTransport`.
#[async_trait]
pub trait ConsensusTransport: Send + Sync + 'static {
    /// Send a message to a peer and wait for a response.
    ///
    /// This is the primary RPC path for AppendEntries, Vote, and
    /// snapshot header messages. The response is the raw bytes from
    /// the peer.
    async fn send_rpc(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<Vec<u8>, ConsensusTransportError>;

    /// Send a message to a peer without waiting for a response.
    ///
    /// Used for snapshot data chunks where the response arrives via
    /// a separate channel (pending_responses in MeshRaftNetwork).
    async fn send_fire_and_forget(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), ConsensusTransportError>;
}

/// Adapter that wraps `MeshTransport` and implements `ConsensusTransport`.
///
/// This is the bridge between the abstract consensus transport trait
/// and the concrete mesh transport implementation.
pub struct MeshConsensusTransportAdapter {
    inner: Arc<crate::transport::MeshTransport>,
}

impl MeshConsensusTransportAdapter {
    pub fn new(transport: Arc<crate::transport::MeshTransport>) -> Self {
        Self { inner: transport }
    }
}

#[async_trait]
impl ConsensusTransport for MeshConsensusTransportAdapter {
    async fn send_rpc(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<Vec<u8>, ConsensusTransportError> {
        self.inner
            .send_message_to_peer_with_response(peer_id, message)
            .await
            .map_err(|e| ConsensusTransportError::SendFailed(format!("{:?}", e)))
    }

    async fn send_fire_and_forget(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), ConsensusTransportError> {
        self.inner
            .send_message_to_peer(peer_id, message)
            .await
            .map_err(|e| ConsensusTransportError::SendFailed(format!("{:?}", e)))
    }
}

/// Abstraction for reading stale records from a local DHT cache.
///
/// Used by `RaftAwareClient::stale_read_cache` to provide a fallback
/// read path without depending directly on `RecordStoreManager`.
/// The caller maps Raft namespaces to DHT keys; this trait just
/// provides the raw record value.
#[async_trait]
pub trait RecordReader: Send + Sync {
    /// Read a record value by its DHT key.
    ///
    /// Returns `Some(value)` if the record exists and is not expired,
    /// `None` otherwise.
    fn get_record_value(&self, key: &str) -> Option<Vec<u8>>;
}
