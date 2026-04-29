use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;

use openraft::RaftTypeConfig;
use openraft::network::v2::RaftNetworkV2;
use openraft::network::Backoff;
use openraft::network::RPCOption;
use openraft::raft::{AppendEntriesRequest, AppendEntriesResponse, VoteRequest, VoteResponse, SnapshotResponse};
use openraft::errors::{RPCError, Unreachable, StreamingError};
use openraft::OptionalSend;
use openraft::type_config::alias::{SnapshotOf, VoteOf};
use tokio::sync::RwLock;

use crate::mesh::backend::MeshBackendPool;
use crate::mesh::protocol::{RaftMsgType, RaftPayload as MeshRaftPayload, MeshMessage, ArcStr};
use crate::mesh::MeshProxy;

pub struct MeshRaftNetwork<C: RaftTypeConfig> {
    backend: Arc<MeshBackendPool>,
    proxy: Arc<MeshProxy>,
    target: String,
    pending_responses: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: RaftTypeConfig> MeshRaftNetwork<C> {
    pub fn new(backend: Arc<MeshBackendPool>, proxy: Arc<MeshProxy>, target: String) -> Self {
        Self {
            backend,
            proxy,
            target,
            pending_responses: Arc::new(RwLock::new(HashMap::new())),
            _phantom: std::marker::PhantomData,
        }
    }

    async fn send_raw(
        &self,
        msg_type: RaftMsgType,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, RPCError<C>> {
        let payload = MeshRaftPayload { msg_type, data };

        let body = postcard::to_stdvec(&payload)
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let request_id = uuid::Uuid::new_v4().to_string();

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        {
            let mut pending = self.pending_responses.write().await;
            pending.insert(request_id.clone(), response_tx);
        }

        let raft_msg = MeshMessage::Raft {
            target_node_id: ArcStr::from(self.target.clone()),
            payload: MeshRaftPayload {
                msg_type,
                data: body,
            },
        };

        let transport_arc = self.proxy.get_transport();
        let transport = {
            let guard = transport_arc.read();
            guard.clone()
        };

        let transport = match transport {
            Some(t) => t,
            None => {
                return Err(RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "Transport not available",
                ))));
            }
        };

        transport.send_message_to_peer(&self.target, &raft_msg).await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let timeout = Duration::from_secs(5);
        tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Raft RPC timeout",
            ))))?
            .map_err(|_| RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Response channel closed",
            ))))
    }

    pub async fn handle_response(&self, request_id: &str, data: Vec<u8>) {
        let mut pending = self.pending_responses.write().await;
        if let Some(sender) = pending.remove(request_id) {
            let _ = sender.send(data);
        }
    }
}

impl<C: RaftTypeConfig> RaftNetworkV2<C> for MeshRaftNetwork<C>
where
    C::NodeId: std::fmt::Display + Send + 'static,
    C::Node: Send + 'static,
{
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<C>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<C>, RPCError<C>> {
        let payload = postcard::to_stdvec(&rpc)
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let data = self.send_raw(RaftMsgType::AppendEntries, payload).await?;

        postcard::from_bytes(&data)
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<C>,
        _option: RPCOption,
    ) -> Result<VoteResponse<C>, RPCError<C>> {
        let payload = postcard::to_stdvec(&rpc)
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let data = self.send_raw(RaftMsgType::VoteRequest, payload).await?;

        postcard::from_bytes(&data)
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))
    }

    async fn full_snapshot(
        &mut self,
        _vote: VoteOf<C>,
        _snapshot: SnapshotOf<C>,
        _cancel: impl Future<Output = openraft::errors::ReplicationClosed> + OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<C>, StreamingError<C>> {
        Err(StreamingError::Unreachable(Unreachable::new(&std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "full_snapshot not implemented for mesh transport",
        ))))
    }

    fn backoff(&self) -> Backoff {
        Backoff::new(std::iter::repeat(std::time::Duration::from_millis(200)))
    }
}

#[derive(Clone)]
pub struct MeshRaftNetworkFactory {
    backend: Arc<MeshBackendPool>,
    proxy: Arc<MeshProxy>,
}

impl MeshRaftNetworkFactory {
    pub fn new(backend: Arc<MeshBackendPool>, proxy: Arc<MeshProxy>) -> Self {
        Self { backend, proxy }
    }
}

impl<C> openraft::network::RaftNetworkFactory<C> for MeshRaftNetworkFactory
where
    C: RaftTypeConfig,
    C::NodeId: std::fmt::Display + Send + 'static,
    C::Node: Send + 'static,
{
    type Network = MeshRaftNetwork<C>;

    async fn new_client(&mut self, target: C::NodeId, _node: &C::Node) -> Self::Network {
        tracing::debug!("Creating Raft network client for target: {}", target);
        MeshRaftNetwork::new(self.backend.clone(), self.proxy.clone(), target.to_string())
    }
}