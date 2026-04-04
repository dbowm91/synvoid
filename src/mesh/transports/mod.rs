#![allow(unused_variables, async_fn_in_trait)]

use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;

use crate::mesh::config::MeshNodeRole;
use crate::mesh::protocol::MeshMessage;

pub mod manager;
pub mod quic;
pub mod stack;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MeshTransportType {
    #[default]
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportHint {
    #[default]
    Default,
    LowLatency,
    HighThroughput,
    Reliable,
}

impl TransportHint {
    pub fn is_low_latency(&self) -> bool {
        matches!(self, TransportHint::LowLatency)
    }

    pub fn is_high_throughput(&self) -> bool {
        matches!(self, TransportHint::HighThroughput)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshTransportError {
    #[error("Transport not available")]
    NotAvailable,
    #[error("Peer not connected: {0}")]
    PeerNotConnected(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Not implemented for this transport")]
    NotImplemented,
    #[error("Timeout")]
    Timeout,
}

#[derive(Debug, Clone)]
pub struct DatagramPacket {
    pub source_node: String,
    pub peer_id: String,
    pub data: Bytes,
    pub received_at: Instant,
}

pub trait MeshTransportTrait: Send + Sync {
    fn transport_type(&self) -> MeshTransportType;

    fn is_connected(&self, peer_id: &str) -> bool;

    fn get_peer_address(&self, peer_id: &str) -> Option<String>;

    async fn send_stream(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError>;

    async fn send_datagram(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError>;

    async fn broadcast_datagram(&self, message: &MeshMessage) -> Result<(), MeshTransportError>;

    fn get_connected_peers(&self) -> Vec<String>;

    fn local_addresses(&self) -> Vec<String>;

    fn is_available(&self) -> bool;
}

#[async_trait]
pub trait MeshPeerConnectionTrait: Send + Sync {
    fn peer_id(&self) -> &str;
    fn address(&self) -> &str;
    fn role(&self) -> MeshNodeRole;
    fn upstreams(&self) -> Vec<String>;
    fn connected_at(&self) -> Instant;
    fn last_seen(&self) -> Instant;

    async fn send_stream(&self, message: &MeshMessage) -> Result<(), MeshTransportError>;
    async fn send_datagram(&self, message: &MeshMessage) -> Result<(), MeshTransportError>;
}

pub trait MeshDatagramHandler: Send + Sync {
    fn handle_datagram(&self, packet: DatagramPacket);
}

pub use manager::{
    MeshTransportManager, PeerTransportState, DEFAULT_MAX_RETRIES, RETRY_BACKOFF_BASE_MS,
    RETRY_BACKOFF_MAX_MS,
};
pub use quic::QuicMeshTransport;
pub use stack::MeshTransportStack;
