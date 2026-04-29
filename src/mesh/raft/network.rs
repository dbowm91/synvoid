use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use http::Request;
use http_body_util::BodyExt;

use openraft::RaftTypeConfig;
use openraft::network::v2::RaftNetworkV2;
use openraft::network::Backoff;
use openraft::network::RPCOption;
use openraft::raft::{AppendEntriesRequest, AppendEntriesResponse, VoteRequest, VoteResponse, SnapshotResponse};
use openraft::errors::{RPCError, Unreachable, StreamingError};
use openraft::OptionalSend;
use openraft::type_config::alias::{SnapshotOf, VoteOf};

use crate::mesh::backend::MeshBackendPool;
use crate::mesh::protocol::{RaftMsgType, RaftPayload as MeshRaftPayload};
use crate::mesh::MeshProxy;

pub struct MeshRaftNetwork<C: RaftTypeConfig> {
    backend: Arc<MeshBackendPool>,
    proxy: Arc<MeshProxy>,
    target: String,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: RaftTypeConfig> MeshRaftNetwork<C> {
    pub fn new(backend: Arc<MeshBackendPool>, proxy: Arc<MeshProxy>, target: String) -> Self {
        Self {
            backend,
            proxy,
            target,
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

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/raft")
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(Full::<Bytes>::new(Bytes::from(body)))
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let resp = self
            .proxy
            .route_request(&self.target, request)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?
            .to_bytes();

        Ok(body.to_vec())
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