use std::sync::Arc;
use std::time::Duration;

use crate::mesh::backend::MeshBackendPool;
use crate::mesh::dht::RecordStoreManager;
use crate::mesh::protocol::{MeshMessage, ArcStr};
use crate::mesh::raft::state_machine::{Namespace, RaftCommand};
use crate::mesh::transport::MeshTransport;
use crate::mesh::MeshConfig;

#[derive(Debug, Clone)]
pub enum ConsistentReadSource {
    RaftLeader,
    DhtStale,
}

#[derive(Debug, Clone)]
pub struct ConsistentReadResult {
    pub value: Option<Vec<u8>>,
    pub source: ConsistentReadSource,
    pub leader_node_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RaftAwareClientError {
    #[error("No Global nodes available")]
    NoGlobalNodes,
    #[error("Raft cluster unreachable")]
    RaftUnreachable,
    #[error("Request timed out after {0:?}")]
    Timeout(Duration),
    #[error("DHT lookup failed")]
    DhtFailed,
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Raft write failed: {0}")]
    RaftWriteFailed(String),
    #[error("Not the leader")]
    NotLeader,
}

pub struct RaftAwareClient {
    backend_pool: Arc<MeshBackendPool>,
    transport: Arc<MeshTransport>,
    config: Arc<MeshConfig>,
    record_store: Option<Arc<RecordStoreManager>>,
}

impl RaftAwareClient {
    pub fn new(
        backend_pool: Arc<MeshBackendPool>,
        transport: Arc<MeshTransport>,
        config: Arc<MeshConfig>,
        record_store: Option<Arc<RecordStoreManager>>,
    ) -> Self {
        Self {
            backend_pool,
            transport,
            config,
            record_store,
        }
    }

    pub async fn raft_write(
        &self,
        namespace: Namespace,
        key: String,
        value: Vec<u8>,
    ) -> Result<u64, RaftAwareClientError> {
        let global_nodes = self.get_global_node_ids().await;
        if global_nodes.is_empty() {
            return Err(RaftAwareClientError::NoGlobalNodes);
        }

        let leader_node_id = self.find_leader_node_id().await
            .ok_or(RaftAwareClientError::RaftUnreachable)?;

        let request_id = uuid::Uuid::new_v4().to_string();
        let timeout = Duration::from_secs(10);

        let command = RaftCommand::Set {
            namespace: namespace.clone(),
            key: key.clone(),
            value: value.clone(),
        };

        let command_bytes = crate::serialization::serialize(&command)
            .map_err(|e| RaftAwareClientError::RaftWriteFailed(e.to_string()))?;

        let raft_payload = crate::mesh::protocol::RaftPayload {
            msg_type: crate::mesh::protocol::RaftMsgType::AppendEntries,
            data: command_bytes,
        };

        let raft_msg = MeshMessage::Raft {
            target_node_id: ArcStr::from(leader_node_id.clone()),
            payload: raft_payload,
        };

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        {
            let pending = self.transport.get_pending_consistent_read_responses().await;
            let mut guard = pending.lock().await;
            guard.insert(request_id.clone(), response_tx);
        }

        self.transport.send_message_to_peer(&leader_node_id, &raft_msg).await
            .map_err(|e| RaftAwareClientError::InvalidResponse(e.to_string()))?;

        let response = tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| RaftAwareClientError::Timeout(timeout))?
            .map_err(|_| RaftAwareClientError::RaftUnreachable)?;

        match response {
            MeshMessage::ConsistentReadResponse { value: Some(v), .. } => {
                let commit_index = u64::from_le_bytes(v.try_into()
                    .map_err(|_| RaftAwareClientError::InvalidResponse("Invalid commit index".to_string()))?);
                Ok(commit_index)
            }
            MeshMessage::NotLeader { .. } => {
                Err(RaftAwareClientError::NotLeader)
            }
            _ => {
                Err(RaftAwareClientError::InvalidResponse("Unexpected response".to_string()))
            }
        }
    }

    async fn find_leader_node_id(&self) -> Option<String> {
        let peers = self.transport.get_topology().get_all_peers().await;
        peers
            .into_iter()
            .find(|p| p.role.is_global())
            .map(|p| p.node_id)
    }

    pub async fn consistent_read(
        &self,
        namespace: Namespace,
        key: &str,
    ) -> Result<ConsistentReadResult, RaftAwareClientError> {
        if self.config.role.is_global() {
            return self.consistent_read_local(namespace, key).await;
        }
        self.consistent_read_via_global(namespace, key).await
    }

    async fn consistent_read_local(
        &self,
        _namespace: Namespace,
        _key: &str,
    ) -> Result<ConsistentReadResult, RaftAwareClientError> {
        let peers = self.transport.get_topology().get_all_peers().await;
        if let Some(peer) = peers.iter().find(|p| p.role.is_global()) {
            return Ok(ConsistentReadResult {
                value: None,
                source: ConsistentReadSource::RaftLeader,
                leader_node_id: Some(peer.node_id.clone()),
            });
        }
        Err(RaftAwareClientError::RaftUnreachable)
    }

    async fn consistent_read_via_global(
        &self,
        namespace: Namespace,
        key: &str,
    ) -> Result<ConsistentReadResult, RaftAwareClientError> {
        let global_nodes = self.get_global_node_ids().await;
        if global_nodes.is_empty() {
            tracing::warn!("No global nodes known for consistent read, falling back to DHT");
            return self.fallback_to_dht(namespace, key).await;
        }

        let request_id = uuid::Uuid::new_v4().to_string();
        let timeout = Duration::from_secs(5);
        let mut last_error = RaftAwareClientError::NoGlobalNodes;

        for global_node_id in &global_nodes {
            let request = MeshMessage::ConsistentReadRequest {
                request_id: ArcStr::from(request_id.clone()),
                namespace: namespace.clone(),
                key: ArcStr::from(key.to_string()),
                requesting_node_id: ArcStr::from(self.config.node_id()),
                timestamp: crate::utils::safe_unix_timestamp(),
            };

            match self.send_message_and_wait_for_response(global_node_id, request, timeout).await {
                Ok(MeshMessage::ConsistentReadResponse { value, leader_node_id, .. }) => {
                    let leader_str = leader_node_id.as_ref().map(|s| s.to_string());
                    return Ok(ConsistentReadResult {
                        value,
                        source: ConsistentReadSource::RaftLeader,
                        leader_node_id: leader_str,
                    });
                }
                Ok(MeshMessage::NotLeader { leader_node_id, .. }) => {
                    if let Some(leader) = leader_node_id {
                        let leader_str = leader.to_string();
                        let retry_request = MeshMessage::ConsistentReadRequest {
                            request_id: ArcStr::from(uuid::Uuid::new_v4().to_string()),
                            namespace: namespace.clone(),
                            key: ArcStr::from(key.to_string()),
                            requesting_node_id: ArcStr::from(self.config.node_id()),
                            timestamp: crate::utils::safe_unix_timestamp(),
                        };
                        if let Ok(MeshMessage::ConsistentReadResponse { value, .. }) =
                            self.send_message_and_wait_for_response(&leader_str, retry_request, timeout).await
                        {
                            return Ok(ConsistentReadResult {
                                value,
                                source: ConsistentReadSource::RaftLeader,
                                leader_node_id: Some(leader_str),
                            });
                        }
                    }
                }
                Ok(other) => {
                    last_error = RaftAwareClientError::InvalidResponse(format!(
                        "Unexpected message type: {:?}",
                        other
                    ));
                }
                Err(e) => {
                    last_error = e;
                }
            }
        }

        tracing::warn!(
            "All Global nodes failed for consistent read, falling back to DHT: {:?}",
            last_error
        );
        self.fallback_to_dht(namespace, key).await
    }

    async fn fallback_to_dht(
        &self,
        namespace: Namespace,
        key: &str,
    ) -> Result<ConsistentReadResult, RaftAwareClientError> {
        let record_store = self.record_store.as_ref().ok_or(
            RaftAwareClientError::DhtFailed,
        )?;

        let dht_key = self.build_dht_key(namespace, key);
        let record = record_store.get_record(&dht_key).ok_or(
            RaftAwareClientError::DhtFailed,
        )?;

        Ok(ConsistentReadResult {
            value: Some(record.value),
            source: ConsistentReadSource::DhtStale,
            leader_node_id: None,
        })
    }

    async fn send_message_and_wait_for_response(
        &self,
        peer_id: &str,
        message: MeshMessage,
        timeout: Duration,
    ) -> Result<MeshMessage, RaftAwareClientError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let request_id = match &message {
            MeshMessage::ConsistentReadRequest { request_id, .. } => request_id.to_string(),
            _ => uuid::Uuid::new_v4().to_string(),
        };

        {
            let pending = self.transport.get_pending_consistent_read_responses().await;
            let mut guard = pending.lock().await;
            guard.insert(request_id.clone(), response_tx);
        }

        self.transport.send_message_to_peer(peer_id, &message).await
            .map_err(|e| RaftAwareClientError::InvalidResponse(e.to_string()))?;

        tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| RaftAwareClientError::Timeout(timeout))?
            .map_err(|_| RaftAwareClientError::RaftUnreachable)
    }

    async fn get_global_node_ids(&self) -> Vec<String> {
        let peers = self.transport.get_topology().get_all_peers().await;
        peers
            .into_iter()
            .filter(|p| p.role.is_global())
            .map(|p| p.node_id)
            .collect()
    }

    fn build_dht_key(&self, namespace: Namespace, key: &str) -> String {
        match namespace {
            Namespace::Org => format!("org:{}", key),
            Namespace::Intel => format!("intel:{}", key),
            Namespace::Revocation => format!("revocation:{}", key),
        }
    }
}

impl Default for RaftAwareClient {
    fn default() -> Self {
        panic!("RaftAwareClient::default should not be used directly")
    }
}