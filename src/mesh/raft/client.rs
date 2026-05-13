use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};

use crate::mesh::backend::MeshBackendPool;
use crate::mesh::dht::RecordStoreManager;
use crate::mesh::protocol::{ArcStr, MeshMessage};
use crate::mesh::raft::edge_replica::EdgeReplicaManager;
use crate::mesh::raft::instance::RaftInstance;
use crate::mesh::raft::state_machine::{
    ClientProposalPayload, CommandKind, Namespace, RaftCommand,
};
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

#[derive(Debug, Clone)]
struct LeaderCache {
    leader_node_id: Option<String>,
    cached_at: Instant,
    ttl: Duration,
}

impl LeaderCache {
    fn new(ttl: Duration) -> Self {
        Self {
            leader_node_id: None,
            cached_at: Instant::now() - ttl - Duration::from_secs(1),
            ttl,
        }
    }

    fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }

    fn update(&mut self, leader_node_id: Option<String>) {
        self.leader_node_id = leader_node_id;
        self.cached_at = Instant::now();
    }

    #[allow(dead_code)]
    fn invalidate(&mut self) {
        self.cached_at = Instant::now() - self.ttl - Duration::from_secs(1);
    }
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
    _backend_pool: Arc<MeshBackendPool>,
    transport: Arc<MeshTransport>,
    config: Arc<MeshConfig>,
    record_store: Option<Arc<RecordStoreManager>>,
    raft_instance: Arc<RwLock<Option<Arc<RaftInstance>>>>,
    edge_replica_manager: Arc<RwLock<Option<Arc<EdgeReplicaManager>>>>,
    leader_cache: Arc<Mutex<LeaderCache>>,
}

impl RaftAwareClient {
    pub fn new(
        backend_pool: Arc<MeshBackendPool>,
        transport: Arc<MeshTransport>,
        config: Arc<MeshConfig>,
        record_store: Option<Arc<RecordStoreManager>>,
    ) -> Self {
        Self {
            _backend_pool: backend_pool,
            transport,
            config,
            record_store,
            raft_instance: Arc::new(RwLock::new(None)),
            edge_replica_manager: Arc::new(RwLock::new(None)),
            leader_cache: Arc::new(Mutex::new(LeaderCache::new(Duration::from_secs(5)))),
        }
    }

    pub async fn set_edge_replica_manager(&self, manager: Arc<EdgeReplicaManager>) {
        *self.edge_replica_manager.write().await = Some(manager);
    }

    pub async fn set_raft_instance(&mut self, instance: Arc<RaftInstance>) {
        *self.raft_instance.write().await = Some(instance);
    }

    pub fn start_reconciliation_loop(self: Arc<Self>) {
        if self.config.role.is_global() {
            return;
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = self.reconcile_with_leader().await {
                    tracing::debug!("Raft reconciliation skipped or failed: {:?}", e);
                }
            }
        });
    }

    async fn reconcile_with_leader(&self) -> Result<(), RaftAwareClientError> {
        let manager_guard = self.edge_replica_manager.read().await;
        let Some(ref manager) = *manager_guard else {
            return Ok(());
        };

        let last_sync_index = manager.get_last_sync_index().unwrap_or(0);
        let leader_node_id = self
            .find_leader_node_id()
            .await
            .ok_or(RaftAwareClientError::RaftUnreachable)?;

        let request_id = uuid::Uuid::new_v4().to_string();
        let request = MeshMessage::ReplicaSyncRequest {
            request_id: ArcStr::from(request_id.clone()),
            last_sync_index,
            node_id: ArcStr::from(self.config.node_id()),
        };

        match self
            .send_message_and_wait_for_response(&leader_node_id, request, Duration::from_secs(10))
            .await
        {
            Ok(MeshMessage::ReplicaSyncResponse {
                current_index,
                snapshot_required,
                ..
            }) => {
                if snapshot_required {
                    tracing::info!(
                        "Raft reconciliation: snapshot required (last={}, current={})",
                        last_sync_index,
                        current_index
                    );
                    // In a future wave, trigger full snapshot transfer
                } else if current_index > last_sync_index {
                    tracing::info!(
                        "Raft reconciliation: catching up from {} to {}",
                        last_sync_index,
                        current_index
                    );
                    // For now, update local index to indicate we are converged at this point
                    manager.set_last_sync_index(current_index).ok();
                }
            }
            _ => {
                return Err(RaftAwareClientError::InvalidResponse(
                    "Failed to get sync response".to_string(),
                ))
            }
        }

        Ok(())
    }

    pub async fn raft_write(
        &self,
        namespace: Namespace,
        key: String,
        value: Vec<u8>,
    ) -> Result<u64, RaftAwareClientError> {
        let timeout = Duration::from_secs(5);
        if self.config.role.is_global() {
            match tokio::time::timeout(timeout, self.raft_write_local(namespace, key, value)).await {
                Ok(res) => res,
                Err(_) => {
                    tracing::warn!("Local Raft write timed out - possible quorum loss. Operating in degradation mode.");
                    Err(RaftAwareClientError::RaftWriteFailed("Timeout".into()))
                }
            }
        } else {
            match tokio::time::timeout(timeout, self.raft_write_via_global(namespace, key, value)).await {
                Ok(res) => res,
                Err(_) => {
                    tracing::warn!("Remote Raft write timed out - possible quorum loss. Operating in degradation mode.");
                    Err(RaftAwareClientError::RaftUnreachable)
                }
            }
        }
    }

    async fn raft_write_local(
        &self,
        namespace: Namespace,
        key: String,
        value: Vec<u8>,
    ) -> Result<u64, RaftAwareClientError> {
        let raft_instance_guard = self.raft_instance.read().await;
        let instance = match raft_instance_guard.as_ref() {
            Some(i) => i,
            None => {
                return Err(RaftAwareClientError::RaftWriteFailed(
                    "No local Raft instance".to_string(),
                ));
            }
        };

        if !instance.is_leader().await {
            return Err(RaftAwareClientError::NotLeader);
        }

        let source_node_id = self.config.node_id();
        let timestamp = crate::utils::safe_unix_timestamp();
        let nonce = rand::random::<u64>();

        let signer = self.transport.mesh_signer.as_ref();
        let signature = signer.map(|s| {
            let payload = ClientProposalPayload::new(
                namespace.clone(),
                key.clone(),
                &value,
                CommandKind::Set,
                source_node_id.clone(),
                timestamp,
                nonce,
            );
            s.sign(&payload.get_signable_content())
        });

        let command = RaftCommand::Set {
            namespace,
            key,
            value,
            source_node_id: Some(source_node_id),
            signature,
        };

        let commit_index = instance
            .client_write(command)
            .await
            .map_err(|e| RaftAwareClientError::RaftWriteFailed(e.to_string()))?;

        Ok(commit_index)
    }

    async fn raft_write_via_global(
        &self,
        namespace: Namespace,
        key: String,
        value: Vec<u8>,
    ) -> Result<u64, RaftAwareClientError> {
        let global_nodes = self.get_global_node_ids().await;
        if global_nodes.is_empty() {
            return Err(RaftAwareClientError::NoGlobalNodes);
        }

        let leader_node_id = self
            .find_leader_node_id()
            .await
            .ok_or(RaftAwareClientError::RaftUnreachable)?;

        self.raft_write_to_leader(namespace, key, value, &leader_node_id)
            .await
    }

    async fn raft_write_to_leader(
        &self,
        namespace: Namespace,
        key: String,
        value: Vec<u8>,
        leader_node_id: &str,
    ) -> Result<u64, RaftAwareClientError> {
        let source_node_id = self.config.node_id();
        let timestamp = crate::utils::safe_unix_timestamp();
        let nonce = rand::random::<u64>();

        let signer = self.transport.mesh_signer.as_ref();
        let signature = signer.map(|s| {
            let payload = ClientProposalPayload::new(
                namespace.clone(),
                key.clone(),
                &value,
                CommandKind::Set,
                source_node_id.clone(),
                timestamp,
                nonce,
            );
            s.sign(&payload.get_signable_content())
        });

        let command = RaftCommand::Set {
            namespace: namespace.clone(),
            key: key.clone(),
            value: value.clone(),
            source_node_id: Some(source_node_id.clone()),
            signature,
        };

        let commit_index = self.send_client_proposal(command, leader_node_id).await?;

        Ok(commit_index)
    }

    async fn send_client_proposal(
        &self,
        command: RaftCommand,
        target_node_id: &str,
    ) -> Result<u64, RaftAwareClientError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let command_bytes = crate::serialization::serialize(&command)
            .map_err(|e| RaftAwareClientError::RaftWriteFailed(e.to_string()))?;

        let raft_payload = crate::mesh::protocol::RaftPayload {
            msg_type: crate::mesh::protocol::RaftMsgType::ClientProposal,
            request_id: Some(request_id),
            data: command_bytes,
        };

        let raft_msg = crate::mesh::protocol::MeshMessage::Raft {
            target_node_id: ArcStr::from(target_node_id.to_string()),
            payload: raft_payload,
        };

        let response_data = self
            .transport
            .send_message_to_peer_with_response(target_node_id, &raft_msg)
            .await
            .map_err(|e| RaftAwareClientError::InvalidResponse(e.to_string()))?;

        let response: crate::mesh::protocol::MeshMessage =
            crate::mesh::protocol::MeshMessage::decode(&response_data).ok_or_else(|| {
                RaftAwareClientError::InvalidResponse("Failed to decode response".to_string())
            })?;

        match response {
            crate::mesh::protocol::MeshMessage::ConsistentReadResponse {
                value: Some(v), ..
            } => {
                let commit_index = u64::from_le_bytes(v.try_into().map_err(|_| {
                    RaftAwareClientError::InvalidResponse("Invalid commit index".to_string())
                })?);
                Ok(commit_index)
            }
            crate::mesh::protocol::MeshMessage::NotLeader {
                leader_node_id: hinted_leader,
                ..
            } => {
                tracing::warn!(
                    "Leader {} rejected proposal, received NotLeader hint: {:?}",
                    target_node_id,
                    hinted_leader
                );
                self.invalidate_leader_cache().await;
                Err(RaftAwareClientError::NotLeader)
            }
            _ => Err(RaftAwareClientError::InvalidResponse(
                "Unexpected response".to_string(),
            )),
        }
    }

    async fn find_leader_node_id(&self) -> Option<String> {
        if let Some(leader) = self.try_get_local_leader().await {
            return Some(leader);
        }

        {
            let cache = self.leader_cache.lock().await;
            if cache.is_valid() {
                return cache.leader_node_id.clone();
            }
        }

        self.refresh_leader_cache().await
    }

    async fn try_get_local_leader(&self) -> Option<String> {
        let guard = self.raft_instance.read().await;
        if let Some(instance) = guard.as_ref() {
            if let Some(leader_id) = instance.get_current_leader().await {
                return Some(leader_id.to_string());
            }
        }
        None
    }

    async fn refresh_leader_cache(&self) -> Option<String> {
        {
            let guard = self.raft_instance.read().await;
            if let Some(instance) = guard.as_ref() {
                if let Some(leader_id) = instance.get_current_leader().await {
                    let leader_str = leader_id.to_string();
                    let mut cache = self.leader_cache.lock().await;
                    cache.update(Some(leader_str.clone()));
                    return Some(leader_str);
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    async fn invalidate_leader_cache(&self) {
        let mut cache = self.leader_cache.lock().await;
        cache.invalidate();
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
        namespace: Namespace,
        key: &str,
    ) -> Result<ConsistentReadResult, RaftAwareClientError> {
        let raft_instance_guard = self.raft_instance.read().await;
        let instance = match raft_instance_guard.as_ref() {
            Some(i) => i,
            None => {
                return Err(RaftAwareClientError::RaftWriteFailed(
                    "No local Raft instance".to_string(),
                ));
            }
        };

        let leader_node_id = instance.get_leader_id().await;
        let is_leader = instance.is_leader().await;

        if !is_leader {
            return Err(RaftAwareClientError::NotLeader);
        }

        let value = instance
            .read(namespace, key)
            .await
            .map_err(|e| RaftAwareClientError::InvalidResponse(e.to_string()))?;

        Ok(ConsistentReadResult {
            value,
            source: ConsistentReadSource::RaftLeader,
            leader_node_id: leader_node_id.map(|id| id.to_string()),
        })
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

            match self
                .send_message_and_wait_for_response(global_node_id, request, timeout)
                .await
            {
                Ok(MeshMessage::ConsistentReadResponse {
                    value,
                    leader_node_id,
                    ..
                }) => {
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
                        if let Ok(MeshMessage::ConsistentReadResponse { value, .. }) = self
                            .send_message_and_wait_for_response(&leader_str, retry_request, timeout)
                            .await
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
        let record_store = self
            .record_store
            .as_ref()
            .ok_or(RaftAwareClientError::DhtFailed)?;

        let dht_key = self.build_dht_key(namespace, key);
        let record = record_store
            .get_record(&dht_key)
            .ok_or(RaftAwareClientError::DhtFailed)?;

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

        self.transport
            .send_message_to_peer(peer_id, &message)
            .await
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
            Namespace::AuthorizedGlobalNodes => format!("auth_node:{}", key),
        }
    }

    pub async fn query_leader_for_record(
        &self,
        namespace: Namespace,
        key: &str,
    ) -> Result<Option<Vec<u8>>, RaftAwareClientError> {
        if self.config.role.is_global() {
            return Err(RaftAwareClientError::InvalidResponse(
                "Global nodes should not query leader for records".to_string(),
            ));
        }

        let global_nodes = self.get_global_node_ids().await;
        if global_nodes.is_empty() {
            return Err(RaftAwareClientError::NoGlobalNodes);
        }

        let leader_node_id = self
            .find_leader_node_id()
            .await
            .ok_or(RaftAwareClientError::RaftUnreachable)?;

        let request_id = uuid::Uuid::new_v4().to_string();
        let timeout = Duration::from_secs(5);

        let request = MeshMessage::ConsistentReadRequest {
            request_id: ArcStr::from(request_id.clone()),
            namespace: namespace.clone(),
            key: ArcStr::from(key.to_string()),
            requesting_node_id: ArcStr::from(self.config.node_id()),
            timestamp: crate::utils::safe_unix_timestamp(),
        };

        let response = self
            .send_message_and_wait_for_response(&leader_node_id, request, timeout)
            .await;

        match response {
            Ok(MeshMessage::ConsistentReadResponse { value, .. }) => Ok(value),
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
                    match self
                        .send_message_and_wait_for_response(&leader_str, retry_request, timeout)
                        .await
                    {
                        Ok(MeshMessage::ConsistentReadResponse { value, .. }) => Ok(value),
                        Ok(other) => Err(RaftAwareClientError::InvalidResponse(format!(
                            "Unexpected response type: {:?}",
                            other
                        ))),
                        Err(e) => Err(e),
                    }
                } else {
                    Err(RaftAwareClientError::RaftUnreachable)
                }
            }
            Ok(other) => Err(RaftAwareClientError::InvalidResponse(format!(
                "Unexpected response type: {:?}",
                other
            ))),
            Err(e) => Err(e),
        }
    }

    pub async fn query_leader_for_record_with_retry(
        &self,
        namespace: Namespace,
        key: &str,
        max_retries: u32,
    ) -> Result<Option<Vec<u8>>, RaftAwareClientError> {
        let mut last_error = RaftAwareClientError::RaftUnreachable;
        let mut backoff_ms = 100;

        for attempt in 0..max_retries {
            match self.query_leader_for_record(namespace.clone(), key).await {
                result @ Ok(_) => return result,
                Err(e) => {
                    last_error = e;
                    if attempt < max_retries - 1 {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(2000);
                    }
                }
            }
        }

        Err(last_error)
    }
}

impl Default for RaftAwareClient {
    fn default() -> Self {
        panic!("RaftAwareClient::default should not be used directly")
    }
}
