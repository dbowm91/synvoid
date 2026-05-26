use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::process::ProcessManager;
use crate::supervisor::state::SupervisorState;

// Import generated types
pub mod proto {
    tonic::include_proto!("synvoid.control");
}

use proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use proto::{
    ApplyUpgradeRequest, ApplyUpgradeResponse, BlockRequest, BlockResponse, ReloadRequest,
    ReloadResponse, StageBinaryRequest, StageBinaryResponse, Stats, StatusRequest,
    StatusResponse, StopRequest, StopResponse, UnblockRequest, UnblockResponse,
    UpgradeStatusRequest, UpgradeStatusResponse, WorkerInfo,
};

pub struct ControlPlaneService {
    process_manager: Arc<ProcessManager>,
    state: SupervisorState,
}

impl ControlPlaneService {
    pub fn new(process_manager: Arc<ProcessManager>, state: SupervisorState) -> Self {
        Self {
            process_manager,
            state,
        }
    }
}

#[tonic::async_trait]
impl ControlPlane for ControlPlaneService {
    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let pm_status = self.process_manager.get_status();

        let workers = pm_status
            .workers
            .into_iter()
            .map(|w| WorkerInfo {
                id: w.id as u32,
                pid: w.pid,
                port: w.port as u32,
                status: w.status,
                requests: w.requests,
                blocked: w.blocked,
            })
            .collect();

        Ok(Response::new(StatusResponse {
            pid: std::process::id(),
            uptime_secs: self.state.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            workers,
            stats: Some(Stats {
                total_requests: pm_status.stats.total_requests,
                blocked_last_hour: pm_status.stats.blocked_last_hour,
                challenged_last_hour: pm_status.stats.challenged_last_hour,
                active_blocks: pm_status.stats.active_blocks as u64,
            }),
        }))
    }

    async fn reload_config(
        &self,
        _request: Request<ReloadRequest>,
    ) -> Result<Response<ReloadResponse>, Status> {
        tracing::info!("gRPC: Reloading configuration");
        let mut config = self.state.config.write().await;
        config.reload_all();

        Ok(Response::new(ReloadResponse {
            success: true,
            message: "Configuration reloaded".to_string(),
        }))
    }

    async fn stop(&self, request: Request<StopRequest>) -> Result<Response<StopResponse>, Status> {
        let graceful = request.into_inner().graceful;
        tracing::info!("gRPC: Stop request received (graceful: {})", graceful);

        let state_clone = self.state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            state_clone.shutdown().await;
        });

        Ok(Response::new(StopResponse { success: true }))
    }

    async fn block_ip(
        &self,
        request: Request<BlockRequest>,
    ) -> Result<Response<BlockResponse>, Status> {
        let req = request.into_inner();
        let ip = req
            .ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP address"))?;

        tracing::info!("gRPC: Manually blocking IP {} (reason: {})", ip, req.reason);
        self.state
            .block_store
            .block_ip(ip, &req.reason, req.duration_secs, &req.scope);

        Ok(Response::new(BlockResponse { success: true }))
    }

    async fn unblock_ip(
        &self,
        request: Request<UnblockRequest>,
    ) -> Result<Response<UnblockResponse>, Status> {
        let req = request.into_inner();
        let ip = req
            .ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP address"))?;

        tracing::info!("gRPC: Manually unblocking IP {}", ip);
        self.state.block_store.unblock_ip(&ip, &req.scope);

        Ok(Response::new(UnblockResponse { success: true }))
    }

    async fn stage_binary(
        &self,
        request: Request<StageBinaryRequest>,
    ) -> Result<Response<StageBinaryResponse>, Status> {
        let req = request.into_inner();
        let orchestrator = self.state.upgrade_orchestrator.clone()
            .ok_or_else(|| Status::internal("Upgrade orchestrator not initialized"))?;

        match orchestrator.stage(std::path::PathBuf::from(req.binary_path)).await {
            Ok(staged) => Ok(Response::new(StageBinaryResponse {
                success: true,
                checksum: staged.checksum.iter().map(|b| format!("{:02x}", b)).collect(),
                message: format!("Binary staged successfully"),
            })),
            Err(e) => Ok(Response::new(StageBinaryResponse {
                success: false,
                checksum: String::new(),
                message: e.to_string(),
            })),
        }
    }

    async fn apply_upgrade(
        &self,
        _request: Request<ApplyUpgradeRequest>,
    ) -> Result<Response<ApplyUpgradeResponse>, Status> {
        let orchestrator = self.state.upgrade_orchestrator.clone()
            .ok_or_else(|| Status::internal("Upgrade orchestrator not initialized"))?;

        match orchestrator.apply().await {
            Ok(upgraded) => Ok(Response::new(ApplyUpgradeResponse {
                success: true,
                message: "Rolling upgrade completed".to_string(),
                upgraded_count: upgraded as u32,
                failed_count: 0,
            })),
            Err(e) => Ok(Response::new(ApplyUpgradeResponse {
                success: false,
                message: e.to_string(),
                upgraded_count: 0,
                failed_count: 1,
            })),
        }
    }

    async fn get_upgrade_status(
        &self,
        _request: Request<UpgradeStatusRequest>,
    ) -> Result<Response<UpgradeStatusResponse>, Status> {
        let orchestrator = self.state.upgrade_orchestrator.clone()
            .ok_or_else(|| Status::internal("Upgrade orchestrator not initialized"))?;

        let state = orchestrator.get_state().await;

        Ok(Response::new(UpgradeStatusResponse {
            state: format!("{:?}", state.state),
            staged_binary_path: state.staged_binary.as_ref().map(|b| b.path.to_string_lossy().to_string()).unwrap_or_default(),
            staged_binary_checksum: state.staged_binary.as_ref().map(|b| b.checksum.iter().map(|byte| format!("{:02x}", byte)).collect()).unwrap_or_default(),
            staged_at: state.staged_binary.as_ref().map(|b| b.staged_at).unwrap_or(0),
            upgraded_count: state.upgraded_count as u32,
            remaining_count: state.remaining_count as u32,
            rollback_reason: state.rollback_reason.unwrap_or_default(),
        }))
    }
}

pub async fn start_grpc_server(
    addr: std::net::SocketAddr,
    process_manager: Arc<ProcessManager>,
    state: SupervisorState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = ControlPlaneService::new(process_manager, state);

    tracing::info!("Starting Control Plane gRPC server on {}", addr);

    tonic::transport::Server::builder()
        .add_service(ControlPlaneServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}