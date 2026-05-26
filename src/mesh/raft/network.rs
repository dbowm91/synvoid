use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use openraft::errors::{RPCError, StreamingError, Unreachable};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::Backoff;
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::type_config::alias::{SnapshotOf, VoteOf};
use openraft::OptionalSend;
use openraft::RaftTypeConfig;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;

use crate::mesh::backend::MeshBackendPool;
use crate::mesh::protocol::{
    ArcStr, MeshMessage, RaftMsgType, RaftPayload as MeshRaftPayload, RaftSnapshotFrame,
};
use crate::mesh::MeshProxy;

const SNAPSHOT_CHUNK_SIZE: usize = 64 * 1024;

pub struct MeshRaftNetwork<C: RaftTypeConfig> {
    _backend: Arc<MeshBackendPool>,
    proxy: Arc<MeshProxy>,
    target: String,
    _observer_tags: Option<Vec<String>>,
    pending_responses: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: RaftTypeConfig> MeshRaftNetwork<C> {
    pub fn new(
        backend: Arc<MeshBackendPool>,
        proxy: Arc<MeshProxy>,
        target: String,
        observer_tags: Option<Vec<String>>,
    ) -> Self {
        Self {
            _backend: backend,
            proxy,
            target,
            _observer_tags: observer_tags,
            pending_responses: Arc::new(RwLock::new(HashMap::new())),
            _phantom: std::marker::PhantomData,
        }
    }

    async fn send_raw(&self, msg_type: RaftMsgType, data: Vec<u8>) -> Result<Vec<u8>, RPCError<C>> {
        let request_id = uuid::Uuid::new_v4().to_string();

        let payload = MeshRaftPayload {
            msg_type,
            data,
            request_id: Some(request_id.clone()),
        };

        let raft_msg = MeshMessage::Raft {
            target_node_id: ArcStr::from(self.target.clone()),
            payload,
        };

        let transport_arc = self.proxy.get_transport();
        let transport = {
            let guard = transport_arc.read();
            guard.clone()
        };

        let transport = match transport {
            Some(t) => t,
            None => {
                return Err(RPCError::Unreachable(Unreachable::new(
                    &std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "Transport not available",
                    ),
                )));
            }
        };

        let response_data = transport
            .send_message_to_peer_with_response(&self.target, &raft_msg)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        Ok(response_data)
    }

    pub async fn handle_response(&self, request_id: &str, data: Vec<u8>) {
        let mut pending = self.pending_responses.write().await;
        if let Some(sender) = pending.remove(request_id) {
            let _ = sender.send(data);
        }
    }
}

impl RaftNetworkV2<crate::mesh::raft::state_machine::GlobalRegistryConfig>
    for MeshRaftNetwork<crate::mesh::raft::state_machine::GlobalRegistryConfig>
{
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        RPCError<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
    > {
        let data =
            postcard::to_stdvec(&rpc).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let data = self.send_raw(RaftMsgType::AppendEntries, data).await?;

        postcard::from_bytes(&data).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        _option: RPCOption,
    ) -> Result<
        VoteResponse<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        RPCError<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
    > {
        let data =
            postcard::to_stdvec(&rpc).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let data = self.send_raw(RaftMsgType::VoteRequest, data).await?;

        postcard::from_bytes(&data).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        snapshot: SnapshotOf<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        _cancel: impl Future<Output = openraft::errors::ReplicationClosed> + OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<
        SnapshotResponse<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
        StreamingError<crate::mesh::raft::state_machine::GlobalRegistryConfig>,
    > {
        let transport_arc = self.proxy.get_transport();
        let transport = {
            let guard = transport_arc.read();
            guard.clone()
        };

        let transport = match transport {
            Some(t) => t,
            None => {
                return Err(StreamingError::Unreachable(Unreachable::new(
                    &std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "Transport not available",
                    ),
                )));
            }
        };

        let target = self.target.clone();
        let meta = postcard::to_stdvec(&snapshot.meta)
            .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

        let vote_data = postcard::to_stdvec(&vote)
            .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

        let mut snapshot_data = snapshot.snapshot;
        let total_size = snapshot_data
            .len()
            .await
            .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

        let request_id = format!("snapshot-{}", uuid::Uuid::new_v4());
        let header = crate::mesh::protocol::SnapshotHeader {
            request_id: request_id.clone(),
            vote: vote_data,
            meta,
            total_size,
        };
        let header_frame = RaftSnapshotFrame::Header(header);
        let header_bytes = postcard::to_stdvec(&header_frame)
            .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        {
            let mut pending = self.pending_responses.write().await;
            pending.insert(request_id.clone(), response_tx);
        }

        let raft_msg = MeshMessage::Raft {
            target_node_id: ArcStr::from(target.clone()),
            payload: MeshRaftPayload {
                msg_type: RaftMsgType::InstallSnapshot,
                data: header_bytes,
                request_id: Some(request_id.clone()),
            },
        };

        transport
            .send_message_to_peer(&target, &raft_msg)
            .await
            .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

        let chunk_size = SNAPSHOT_CHUNK_SIZE;
        let mut offset = 0u64;

        while offset < total_size {
            let this_chunk_size = (total_size - offset).min(chunk_size as u64) as usize;
            let mut chunk = vec![0u8; this_chunk_size];
            snapshot_data
                .read_exact(&mut chunk)
                .await
                .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

            let is_last = offset + (this_chunk_size as u64) >= total_size;

            let chunk_info = crate::mesh::protocol::SnapshotChunk {
                request_id: request_id.clone(),
                offset,
                is_last,
                data: chunk,
            };
            let chunk_frame = crate::mesh::protocol::RaftSnapshotFrame::Chunk(chunk_info);
            let chunk_bytes = postcard::to_stdvec(&chunk_frame)
                .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

            let chunk_msg = MeshMessage::Raft {
                target_node_id: ArcStr::from(target.clone()),
                payload: MeshRaftPayload {
                    msg_type: RaftMsgType::InstallSnapshot,
                    data: chunk_bytes,
                    request_id: Some(request_id.clone()),
                },
            };

            transport
                .send_message_to_peer(&target, &chunk_msg)
                .await
                .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

            offset += this_chunk_size as u64;
        }

        let timeout = Duration::from_secs(60);
        let response_data = tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| {
                StreamingError::Unreachable(Unreachable::new(&std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Snapshot transfer timeout",
                )))
            })?
            .map_err(|_| {
                StreamingError::Unreachable(Unreachable::new(&std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Response channel closed",
                )))
            })?;

        let response: SnapshotResponse<crate::mesh::raft::state_machine::GlobalRegistryConfig> =
            postcard::from_bytes(&response_data)
                .map_err(|e| StreamingError::Unreachable(Unreachable::new(&e)))?;

        Ok(response)
    }

    fn backoff(&self) -> Option<Backoff> {
        Some(Backoff::new(std::iter::repeat(
            std::time::Duration::from_millis(200),
        )))
    }
}

#[derive(Clone)]
pub struct MeshRaftNetworkFactory {
    backend: Arc<MeshBackendPool>,
    proxy: Arc<MeshProxy>,
    observer_tags: Vec<String>,
}

impl MeshRaftNetworkFactory {
    pub fn new(backend: Arc<MeshBackendPool>, proxy: Arc<MeshProxy>) -> Self {
        Self {
            backend,
            proxy,
            observer_tags: Vec::new(),
        }
    }

    pub fn with_observer_tags(mut self, tags: Vec<String>) -> Self {
        self.observer_tags = tags;
        self
    }
}

impl openraft::network::RaftNetworkFactory<crate::mesh::raft::state_machine::GlobalRegistryConfig>
    for MeshRaftNetworkFactory
{
    type Network = MeshRaftNetwork<crate::mesh::raft::state_machine::GlobalRegistryConfig>;

    async fn new_client(
        &mut self,
        target: <crate::mesh::raft::state_machine::GlobalRegistryConfig as openraft::RaftTypeConfig>::NodeId,
        _node: &<crate::mesh::raft::state_machine::GlobalRegistryConfig as openraft::RaftTypeConfig>::Node,
    ) -> Self::Network {
        tracing::debug!(
            "Creating Raft network client for target: {} with observer_tags: {:?}",
            target,
            self.observer_tags
        );
        MeshRaftNetwork::new(
            self.backend.clone(),
            self.proxy.clone(),
            target.to_string(),
            Some(self.observer_tags.clone()),
        )
    }
}
