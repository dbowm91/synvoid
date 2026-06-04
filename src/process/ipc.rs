use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::metrics::TimingStatsPayload;

use super::ipc_framing::{DEFAULT_BUFFER_SIZE, read_message_sync, write_message_sync};
use super::ipc_signed::{IpcSigner, SignedIpcMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandMethod {
    UnixSocket,
    NamedPipe,
    Signal,
    GRpc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorCommand {
    Stop { graceful: bool },
    ReloadConfig,
    Status,
    HealthCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorStatus {
    #[serde(alias = "master_pid")]
    pub supervisor_pid: u32,
    pub started_at: u64,
    pub uptime_secs: u64,
    pub version: String,
    pub workers: Vec<WorkerStatusInfo>,
    pub stats: StatusStats,
    pub threat_summary: ThreatSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusInfo {
    pub id: usize,
    pub pid: u32,
    pub port: u16,
    pub status: String,
    pub requests: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusStats {
    pub total_requests: u64,
    pub blocked_last_hour: u64,
    pub challenged_last_hour: u64,
    pub proxied_last_hour: u64,
    pub active_blocks: usize,
    pub active_violations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatSummary {
    pub critical_ips: usize,
    pub elevated_ips: usize,
    pub total_blocked_ips: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatIndicatorType {
    IpBlock,
    RateLimitViolation,
    SuspiciousActivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicatorData {
    pub threat_type: ThreatIndicatorType,
    pub indicator_value: String,
    pub severity: ThreatSeverityLevel,
    pub reason: String,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub timestamp: u64,
    pub site_scope: String,
    pub rate_limit_requests: Option<u64>,
    pub rate_limit_window_secs: Option<u64>,
    pub suspicious_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntryData {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePatternData {
    pub category: String,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpuTaskKind {
    Minify,
    GetCompressed,
    PoisonImage,
    YaraScan,
    WasmExecute,
    ServerlessInvoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuTaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuTaskPolicy {
    FailClosed,
    FailOpenWithLog,
    SkipTransform,
    DegradeToInlineSmallOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpuTaskPayload {
    Minify {
        site_id: String,
        path: String,
        encoding: Option<String>,
    },
    GetCompressed {
        site_id: String,
        path: String,
        encoding: String,
    },
    PoisonImage {
        site_id: String,
        body: Vec<u8>,
        last_modified: Option<String>,
        level: Option<String>,
        intensity: Option<f32>,
        seed: Option<u64>,
        max_dimension: Option<u32>,
        jpeg_quality: Option<u8>,
    },
    YaraScan {
        site_id: String,
        body: Vec<u8>,
        excluded_categories: Vec<String>,
    },
    WasmExecute {
        site_id: String,
        plugin_name: String,
        function_name: String,
        input: Vec<u8>,
        timeout_ms: u64,
    },
    ServerlessInvoke {
        site_id: String,
        function_name: String,
        input: Vec<u8>,
        timeout_ms: u64,
    },
    WasmTransformResponse {
        site_id: String,
        plugin_names: Vec<String>,
        status_code: u16,
        body: Vec<u8>,
        env: std::collections::HashMap<String, String>,
        timeout_ms: u64,
    },
}

impl CpuTaskPayload {
    pub fn task_kind(&self) -> CpuTaskKind {
        match self {
            CpuTaskPayload::Minify { .. } => CpuTaskKind::Minify,
            CpuTaskPayload::GetCompressed { .. } => CpuTaskKind::GetCompressed,
            CpuTaskPayload::PoisonImage { .. } => CpuTaskKind::PoisonImage,
            CpuTaskPayload::YaraScan { .. } => CpuTaskKind::YaraScan,
            CpuTaskPayload::WasmExecute { .. } => CpuTaskKind::WasmExecute,
            CpuTaskPayload::ServerlessInvoke { .. } => CpuTaskKind::ServerlessInvoke,
            CpuTaskPayload::WasmTransformResponse { .. } => CpuTaskKind::WasmExecute,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpuTaskResult {
    Minify {
        site_id: String,
        path: String,
        content: Vec<u8>,
        content_type: String,
        encoding: Option<String>,
        queued_encodings: Vec<String>,
    },
    GetCompressed {
        content: Vec<u8>,
    },
    PoisonImage {
        poisoned_body: Vec<u8>,
    },
    YaraScan {
        matches: Vec<String>,
    },
    WasmExecute {
        output: Vec<u8>,
    },
    WasmTransformResponse {
        status_code: u16,
        body: Vec<u8>,
    },
    ServerlessInvoke {
        output: Vec<u8>,
    },
}

impl CpuTaskResult {
    pub fn task_kind(&self) -> CpuTaskKind {
        match self {
            CpuTaskResult::Minify { .. } => CpuTaskKind::Minify,
            CpuTaskResult::GetCompressed { .. } => CpuTaskKind::GetCompressed,
            CpuTaskResult::PoisonImage { .. } => CpuTaskKind::PoisonImage,
            CpuTaskResult::YaraScan { .. } => CpuTaskKind::YaraScan,
            CpuTaskResult::WasmExecute { .. } => CpuTaskKind::WasmExecute,
            CpuTaskResult::WasmTransformResponse { .. } => CpuTaskKind::WasmExecute,
            CpuTaskResult::ServerlessInvoke { .. } => CpuTaskKind::ServerlessInvoke,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpuOffloadStats {
    pub queued_minify: u64,
    pub queued_get_compressed: u64,
    pub queued_poison_image: u64,
    pub queued_yara_scan: u64,
    pub queued_wasm_execute: u64,
    pub queued_serverless_invoke: u64,
    pub active_minify: u64,
    pub active_get_compressed: u64,
    pub active_poison_image: u64,
    pub active_yara_scan: u64,
    pub active_wasm_execute: u64,
    pub active_serverless_invoke: u64,
    pub completed_minify: u64,
    pub completed_get_compressed: u64,
    pub completed_poison_image: u64,
    pub completed_yara_scan: u64,
    pub completed_wasm_execute: u64,
    pub completed_serverless_invoke: u64,
    pub payload_bytes_in_total: u64,
    pub payload_bytes_out_total: u64,
    pub rejected_total: u64,
    pub timeout_total: u64,
    pub failed_total: u64,
    pub submitted_total: u64,
    pub fallback_inline_small_total: u64,
    pub task_duration_ms: HashMap<String, TimingStatsPayload>,
    pub event_loop_lag_ms: u64,
    pub worker_rss_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuTaskErrorCode {
    InvalidRequest,
    Timeout,
    QueueSaturated,
    PayloadTooLarge,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshControlRequest {
    DhtLookup { key: String },
    RaftStatus,
    PeerRegister { node_id: String, address: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshControlResponse {
    DhtValue {
        key: String,
        value: Option<Vec<u8>>,
    },
    RaftStatus {
        leader_id: Option<String>,
        term: u64,
        is_leader: bool,
    },
    PeerRegistered {
        success: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshUpdateNotification {
    PeerJoined { node_id: String, address: String },
    PeerLeft { node_id: String },
    DhtKeyUpdated { key: String },
}

/// Unique identifier for a worker process within the supervisor's pool.
///
/// Worker IDs are assigned sequentially starting from 0. They are used
/// for IPC routing, health checks, and drain operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkerId(pub usize);

impl WorkerId {
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for WorkerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorSeverity::Warning => write!(f, "warning"),
            ErrorSeverity::Error => write!(f, "error"),
            ErrorSeverity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Unknown,
    ConfigLoadFailed,
    SocketBindFailed,
    UpstreamConnectionFailed,
    WorkerPanic,
    ResourceExhausted,
    Timeout,
    AuthenticationFailed,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::Unknown => write!(f, "unknown"),
            ErrorCode::ConfigLoadFailed => write!(f, "config_load_failed"),
            ErrorCode::SocketBindFailed => write!(f, "socket_bind_failed"),
            ErrorCode::UpstreamConnectionFailed => write!(f, "upstream_connection_failed"),
            ErrorCode::WorkerPanic => write!(f, "worker_panic"),
            ErrorCode::ResourceExhausted => write!(f, "resource_exhausted"),
            ErrorCode::Timeout => write!(f, "timeout"),
            ErrorCode::AuthenticationFailed => write!(f, "authentication_failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecuteRequest {
    pub request_id: u64,
    pub plugin_name: String,
    pub function_name: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecuteResponse {
    pub request_id: u64,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessHandleRequest {
    pub request_id: u64,
    pub function_name: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub env_vars: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessHandleResponse {
    pub request_id: u64,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

/// IPC messages exchanged between supervisor and worker processes.
///
/// Messages are serialized as JSON over Unix domain sockets. Each variant
/// IPC Message variants grouped by concern (documentation-level grouping).
///
/// The flat variant structure is maintained for postcard wire-format stability.
/// Use these group names when adding new variants:
///
/// - **Worker Lifecycle**: WorkerStarted, WorkerReady, WorkerHeartbeat,
///   WorkerRequestLog, WorkerShutdownComplete, WorkerError
/// - **Supervisor Commands**: SupervisorShutdown, SupervisorConfigReload,
///   MasterProcessConfigReload, MasterSupervisorConfigReload, MasterHealthCheck,
///   MasterResizeThreadpool, MasterCertReload, HealthCheckAck, WorkerResizeAck
/// - **Cpu Worker**: CpuWorkerStarted, CpuWorkerReady,
///   CpuWorkerHeartbeat, CpuWorkerRequestLog, CpuWorkerShutdownComplete,
///   CpuWorkerBackgroundTasksDone, CpuWorkerResizeAck, CpuWorkerScan,
///   CpuWorkerCacheUpdate, CpuWorkerDrain, CpuWorkerDrained,
///   CpuWorkerDrainStatus, MinifyRequest, MinifyResponse, MinifyError,
///   PoisonImageRequest, PoisonImageResponse, PoisonImageError,
///   GetCompressedRequest, GetCompressedResponse, CpuTaskRequest,
///   CpuTaskCancel, CpuTaskResponse, CpuTaskError
/// - **Threat Intel**: ThreatIndicatorAnnounce, ThreatIndicatorFromMesh,
///   ThreatSyncRequest, ThreatSyncResponse, BlocklistRequest, BlocklistResponse
/// - **Blocklist & Rules**: BlocklistUpdate, RulePatternsUpdate,
///   BlocklistWriteComplete
/// - **Legacy Static Content**: MinifyRequest, MinifyResponse, MinifyError,
///   PoisonImageRequest, PoisonImageResponse, PoisonImageError,
///   GetCompressedRequest, GetCompressedResponse
/// - **App Server**: AppServerStarted, AppServerReady, AppServerHealth,
///   AppServerStopped, AppServerRestarted, AppServerError
/// - **Unified Server**: UnifiedServerWorkerStarted, UnifiedServerWorkerReady,
///   UnifiedServerWorkerHeartbeat, UnifiedServerWorkerShutdownComplete,
///   UnifiedServerWorkerError, UnifiedServerWorkerDrain,
///   UnifiedServerWorkerDrained, UnifiedServerWorkerResize,
///   UnifiedServerWorkerResizeAck
/// - **Worker Drain**: WorkerDrain, WorkerDrained, WorkerConnectionCount,
///   WorkerDrainComplete, WorkerReadyForTraffic
/// - **Upgrade**: UpgradeReady, UpgradeFailed, SupervisorUpgradePrepare,
///   SupervisorUpgradePrepareAck, SupervisorUpgradeCommit,
///   SupervisorUpgradeCommitAck, SupervisorUpgradeRollback,
///   SupervisorUpgradeRollbackAck, SupervisorCommitUpgrade,
///   SupervisorCommitUpgradeAck
/// - **Supervisor**: SupervisorDrainWorkers, SupervisorDrainWorkersAck,
///   SupervisorGetStatus, SupervisorStatusResponse, SupervisorDualSupervisorPrepare,
///   SupervisorDualSupervisorPrepareAck
/// - **Supervisor Drain**: SupervisorDrainMode, SupervisorDrainModeAck,
///   MasterReportConnections, MasterConnectionsReport, MasterStopAccepting,
///   MasterStopAcceptingAck, MasterDrainStatus
/// - **Drain Protocol**: DrainRequest, DrainStatusRequest, DrainStatusResponse,
///   DrainComplete, StopAccepting, StopAcceptingAck, RestoreFromDrain,
///   RestoreFromDrainAck
/// - **Socket Handoff**: SocketHandoffRequest, SocketHandoffReady,
///   SocketHandoffComplete, SocketHandoffFailed, WindowsSocketInfo
/// - **Worker Restart**: RestartWorkerRequest, RestartWorkerResponse
/// - **Plugin**: PluginStateSync, PluginExecuteRequest, PluginExecuteResponse,
///   ServerlessHandleRequest, ServerlessHandleResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum Message {
    WorkerStarted {
        id: WorkerId,
        pid: u32,
        port: u16,
        timestamp: u64,
    },
    WorkerReady {
        id: WorkerId,
    },
    WorkerHeartbeat {
        id: WorkerId,
        timestamp: u64,
        metrics: WorkerMetricsPayload,
    },
    WorkerRequestLog {
        id: WorkerId,
        log: RequestLogPayload,
    },
    WorkerShutdownComplete {
        id: WorkerId,
    },
    WorkerError {
        id: WorkerId,
        error: String,
        severity: ErrorSeverity,
        error_code: ErrorCode,
    },
    MasterShutdown {
        graceful: bool,
        timeout_secs: u64,
    },
    MasterConfigReload {
        config_path: String,
    },
    MasterProcessConfigReload {
        config: crate::config::ProcessManagerConfig,
    },
    MasterSupervisorConfigReload {
        config: crate::config::SupervisorConfig,
    },
    MasterHealthCheck {
        timestamp: u64,
    },
    MasterResizeThreadpool {
        worker_threads: u32,
    },
    MasterCertReload,
    StreamChunk {
        stream_id: u64,
        chunk: Vec<u8>,
        is_eof: bool,
    },
    HealthCheckAck {
        timestamp: u64,
    },
    WorkerResizeAck {
        id: WorkerId,
        worker_threads: u32,
    },
    WorkerCertReload {
        id: WorkerId,
        domains: Vec<String>,
    },
    CpuWorkerStarted {
        worker_id: usize,
        pid: u32,
    },
    CpuWorkerReady {
        worker_id: usize,
    },
    CpuWorkerHeartbeat {
        worker_id: usize,
        timestamp: u64,
        static_cache_hits: u64,
        static_cache_misses: u64,
        cpu_offload_stats: CpuOffloadStats,
    },
    CpuWorkerRequestLog {
        worker_id: usize,
        log: RequestLogPayload,
    },
    CpuWorkerShutdownComplete {
        worker_id: usize,
    },
    CpuWorkerBackgroundTasksDone {
        worker_id: usize,
    },
    CpuWorkerResizeAck {
        worker_id: usize,
        worker_threads: u32,
    },
    CpuWorkerScan {
        site_id: String,
    },
    CpuWorkerCacheUpdate {
        site_id: String,
        path: String,
        minified_path: String,
    },
    UpstreamGlobalStats {
        worker_id: usize,
        backend_stats: HashMap<String, u64>,
    },
    GlobalUpstreamStatsBroadcast {
        aggregated_stats: HashMap<String, u64>,
    },
    CpuWorkerDrain {
        timeout_secs: u64,
        drain_id: u64,
    },
    CpuWorkerDrained {
        worker_id: usize,
        remaining_tasks: u64,
        drain_id: u64,
    },
    CpuWorkerDrainStatus {
        drain_id: u64,
        is_draining: bool,
        active_tasks: u64,
        drain_complete: bool,
    },
    ThreatIndicatorAnnounce {
        worker_id: usize,
        threat_type: ThreatIndicatorType,
        indicator_value: String,
        severity: ThreatSeverityLevel,
        reason: String,
        ttl_seconds: u64,
        site_scope: String,
        rate_limit_requests: Option<u64>,
        rate_limit_window_secs: Option<u64>,
        suspicious_pattern: Option<String>,
    },
    ThreatIndicatorFromMesh {
        worker_id: usize,
        source_node_id: String,
        threat_type: ThreatIndicatorType,
        indicator_value: String,
        severity: ThreatSeverityLevel,
        reason: String,
        ttl_seconds: u64,
        site_scope: String,
    },
    ThreatSyncRequest {
        worker_id: usize,
        from_version: u64,
    },
    ThreatSyncResponse {
        worker_id: usize,
        indicators: Vec<ThreatIndicatorData>,
        version: u64,
    },
    ThreatFeedUpdate {
        indicators: Vec<ThreatIndicatorData>,
        version: u64,
        timestamp: u64,
    },
    BlocklistRequest {
        worker_id: usize,
        from_version: u64,
    },
    BlocklistResponse {
        worker_id: usize,
        blocks: Vec<BlockEntryData>,
        version: u64,
    },
    BlocklistUpdate {
        blocks: Vec<BlockEntryData>,
        version: u64,
    },
    RulePatternsUpdate {
        version: String,
        patterns: Vec<RulePatternData>,
    },
    BlocklistWriteComplete {
        worker_id: usize,
        success: bool,
    },
    MinifyRequest {
        request_id: u64,
        site_id: String,
        path: String,
        encoding: Option<String>,
    },
    MinifyResponse {
        request_id: u64,
        site_id: String,
        path: String,
        content: Vec<u8>,
        content_type: String,
        encoding: Option<String>,
        queued_encodings: Vec<String>,
    },
    MinifyError {
        request_id: u64,
        error: String,
    },
    PoisonImageRequest {
        request_id: u64,
        site_id: String,
        body: Vec<u8>,
        last_modified: Option<String>,
        level: Option<String>,
        intensity: Option<f32>,
        seed: Option<u64>,
        max_dimension: Option<u32>,
        jpeg_quality: Option<u8>,
    },
    PoisonImageResponse {
        request_id: u64,
        poisoned_body: Vec<u8>,
    },
    PoisonImageError {
        request_id: u64,
        error: String,
    },
    GetCompressedRequest {
        request_id: u64,
        site_id: String,
        path: String,
        encoding: String,
    },
    GetCompressedResponse {
        request_id: u64,
        content: Vec<u8>,
    },
    CpuTaskRequest {
        request_id: u64,
        task_kind: CpuTaskKind,
        priority: CpuTaskPriority,
        policy: CpuTaskPolicy,
        deadline_unix_ms: u64,
        payload_size_limit: u64,
        output_size_limit: u64,
        file_payload_path: Option<String>,
        payload: CpuTaskPayload,
    },
    CpuTaskCancel {
        request_id: u64,
        task_kind: CpuTaskKind,
    },
    CpuTaskResponse {
        request_id: u64,
        task_kind: CpuTaskKind,
        result: CpuTaskResult,
    },
    CpuTaskError {
        request_id: u64,
        task_kind: CpuTaskKind,
        code: CpuTaskErrorCode,
        message: String,
        retryable: bool,
    },
    AppServerStarted {
        id: WorkerId,
        site_id: String,
        socket_path: Option<String>,
        pid: u32,
        timestamp: u64,
    },
    AppServerReady {
        id: WorkerId,
        site_id: String,
    },
    AppServerHealth {
        id: WorkerId,
        site_id: String,
        healthy: bool,
        timestamp: u64,
    },
    AppServerStopped {
        id: WorkerId,
        site_id: String,
    },
    AppServerRestarted {
        id: WorkerId,
        site_id: String,
        new_pid: u32,
        timestamp: u64,
    },
    AppServerError {
        id: WorkerId,
        site_id: String,
        error: String,
    },
    UnifiedServerWorkerStarted {
        id: WorkerId,
        pid: u32,
        timestamp: u64,
    },
    UnifiedServerWorkerReady {
        id: WorkerId,
    },
    UnifiedServerWorkerHeartbeat {
        id: WorkerId,
        timestamp: u64,
        metrics: WorkerMetricsPayload,
    },
    UnifiedServerWorkerShutdownComplete {
        id: WorkerId,
    },
    UnifiedServerWorkerError {
        id: WorkerId,
        error: String,
        severity: ErrorSeverity,
        error_code: ErrorCode,
    },
    UnifiedServerWorkerDrain {
        timeout_secs: u64,
        drain_id: u64,
    },
    UnifiedServerWorkerDrained {
        id: WorkerId,
        remaining_connections: u64,
        drain_id: u64,
    },
    UnifiedServerWorkerResize {
        worker_threads: u32,
    },
    UnifiedServerWorkerResizeAck {
        id: WorkerId,
        worker_threads: u32,
    },
    WorkerDrain {
        id: WorkerId,
        timeout_secs: u64,
    },
    WorkerDrained {
        id: WorkerId,
        remaining_connections: u64,
    },
    UpgradeReady {
        mode: UpgradeModePayload,
        new_worker_ids: Vec<WorkerId>,
    },
    UpgradeFailed {
        error: String,
    },
    SupervisorUpgradePrepare {
        binary_path: String,
        config_path: Option<String>,
        version: String,
    },
    SupervisorUpgradePrepareAck {
        ready: bool,
        error: Option<String>,
    },
    SupervisorUpgradeCommit {
        timeout_secs: u64,
    },
    SupervisorUpgradeCommitAck {
        success: bool,
        error: Option<String>,
    },
    SupervisorUpgradeRollback {
        reason: String,
    },
    SupervisorUpgradeRollbackAck {
        success: bool,
        error: Option<String>,
    },
    SupervisorDrainWorkers {
        timeout_secs: u64,
    },
    SupervisorDrainWorkersAck {
        drained_count: usize,
        remaining_connections: u64,
    },
    SupervisorGetStatus,
    SupervisorStatusResponse {
        master_pid: u32,
        workers: Vec<WorkerStatusInfo>,
        uptime_secs: u64,
        version: String,
    },
    SupervisorDualSupervisorPrepare {
        binary_path: String,
        config_path: Option<String>,
        version: String,
    },
    SupervisorDualSupervisorPrepareAck {
        ready: bool,
        error: Option<String>,
    },
    MasterDrainMode {
        graceful_timeout_secs: u64,
        stop_accepting: bool,
    },
    MasterDrainModeAck {
        accepted: bool,
        active_connections: u64,
    },
    MasterReportConnections {},
    MasterConnectionsReport {
        active_connections: u64,
        idle_connections: u64,
        by_worker: Vec<(WorkerId, u64)>,
    },
    MasterStopAccepting {},
    MasterStopAcceptingAck {
        success: bool,
    },
    WorkerConnectionCount {
        id: WorkerId,
        active: u64,
        idle: u64,
    },
    WorkerDrainComplete {
        id: WorkerId,
        connections_handled: u64,
    },
    SupervisorCommitUpgrade {
        old_supervisor_timeout_secs: u64,
    },
    SupervisorCommitUpgradeAck {
        success: bool,
        error: Option<String>,
    },
    SocketHandoffRequest {
        socket_path: String,
    },
    SocketHandoffReady {
        ports: Vec<u16>,
    },
    SocketHandoffComplete {
        success: bool,
        fd_count: usize,
    },
    SocketHandoffFailed {
        error: String,
    },
    SocketHandoffActiveConnection {
        connection_id: u64,
        protocol: String,
        client_addr: String,
    },
    WorkerConnectionHandoff {
        id: WorkerId,
        connection_id: u64,
        protocol: String,
        client_addr: String,
        metadata: HashMap<String, String>,
    },
    WorkerConnectionAdopted {
        id: WorkerId,
        connection_id: u64,
        success: bool,
    },
    WindowsSocketInfo {
        protocol_info: Vec<u8>,
        port: u16,
    },
    DrainRequest {
        timeout_secs: u64,
        drain_id: u64,
    },
    DrainStatusRequest {
        drain_id: u64,
    },
    DrainStatusResponse {
        drain_id: u64,
        is_draining: bool,
        active_connections: u64,
        idle_connections: u64,
        connections_drained: u64,
        drain_elapsed_secs: u64,
        drain_complete: bool,
    },
    DrainComplete {
        drain_id: u64,
        worker_id: WorkerId,
        connections_drained: u64,
    },
    StopAccepting {
        drain_id: u64,
    },
    StopAcceptingAck {
        drain_id: u64,
        accepted: bool,
        active_connections: u64,
    },
    RestoreFromDrain,
    RestoreFromDrainAck {
        success: bool,
    },
    WorkerReadyForTraffic {
        id: WorkerId,
    },
    MasterDrainStatus {
        is_draining: bool,
        active_connections: u64,
        drain_elapsed_secs: u64,
    },
    RestartWorkerRequest {
        id: WorkerId,
    },
    RestartWorkerResponse {
        id: WorkerId,
        success: bool,
        error: Option<String>,
    },
    PluginStateSync {
        plugin_name: String,
        wasm_module_data: Vec<u8>,
    },
    PluginExecuteRequest(PluginExecuteRequest),
    PluginExecuteResponse(PluginExecuteResponse),
    ServerlessHandleRequest(ServerlessHandleRequest),
    ServerlessHandleResponse(ServerlessHandleResponse),
    MeshControlRequest {
        worker_id: usize,
        request: MeshControlRequest,
    },
    MeshControlResponse {
        worker_id: usize,
        response: MeshControlResponse,
    },
    MeshUpdateNotification {
        worker_id: usize,
        notification: MeshUpdateNotification,
    },
    CommandResponse {
        id: WorkerId,
        response: String,
    },
}

const MAX_STRING_LENGTH: usize = 64 * 1024;
const MAX_PATH_LENGTH: usize = 4096;

#[derive(Debug)]
pub struct IpcValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for IpcValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IPC validation error in {}: {}",
            self.field, self.message
        )
    }
}

impl std::error::Error for IpcValidationError {}

impl Message {
    /// Validate string field lengths to prevent memory exhaustion from
    /// maliciously large IPC messages.
    pub fn validate(&self) -> Result<(), IpcValidationError> {
        // Helper: validate a single string field
        fn check_str(
            field: &'static str,
            value: &str,
            max: usize,
        ) -> Result<(), IpcValidationError> {
            if value.len() > max {
                Err(IpcValidationError {
                    field: field.into(),
                    message: format!("{} > {}", value.len(), max),
                })
            } else {
                Ok(())
            }
        }
        // Helper: validate path fields (reject path traversal)
        fn check_path_str(
            field: &'static str,
            value: &str,
            max: usize,
        ) -> Result<(), IpcValidationError> {
            if value.len() > max {
                return Err(IpcValidationError {
                    field: field.into(),
                    message: format!("{} > {}", value.len(), max),
                });
            }
            if value.contains("..") {
                return Err(IpcValidationError {
                    field: field.into(),
                    message: "path traversal detected".into(),
                });
            }
            Ok(())
        }
        // Helper: validate an optional string field
        fn check_opt_str(
            field: &'static str,
            value: &Option<String>,
            max: usize,
        ) -> Result<(), IpcValidationError> {
            if let Some(ref v) = value {
                check_str(field, v, max)
            } else {
                Ok(())
            }
        }
        // Helper: validate an optional path field
        fn check_opt_path_str(
            field: &'static str,
            value: &Option<String>,
            max: usize,
        ) -> Result<(), IpcValidationError> {
            if let Some(ref v) = value {
                check_path_str(field, v, max)
            } else {
                Ok(())
            }
        }
        // Helper: validate a Vec of strings (e.g., pattern lists)
        fn check_str_vec(
            field: &'static str,
            values: &[String],
            max: usize,
        ) -> Result<(), IpcValidationError> {
            for v in values {
                check_str(field, v, max)?;
            }
            Ok(())
        }

        match self {
            // Variants with no string fields — always valid
            Message::WorkerStarted { .. }
            | Message::WorkerReady { .. }
            | Message::WorkerHeartbeat { .. }
            | Message::WorkerShutdownComplete { .. }
            | Message::MasterShutdown { .. }
            | Message::MasterProcessConfigReload { .. }
            | Message::MasterSupervisorConfigReload { .. }
            | Message::MasterHealthCheck { .. }
            | Message::MasterResizeThreadpool { .. }
            | Message::MasterCertReload
            | Message::HealthCheckAck { .. }
            | Message::WorkerResizeAck { .. }
            | Message::WorkerCertReload { .. }
            | Message::CpuWorkerStarted { .. }
            | Message::CpuWorkerReady { .. }
            | Message::CpuWorkerHeartbeat { .. }
            | Message::CpuWorkerShutdownComplete { .. }
            | Message::CpuWorkerBackgroundTasksDone { .. }
            | Message::CpuWorkerResizeAck { .. }
            | Message::CpuWorkerDrain { .. }
            | Message::CpuWorkerDrained { .. }
            | Message::CpuWorkerDrainStatus { .. }
            | Message::ThreatSyncRequest { .. }
            | Message::ThreatSyncResponse { .. }
            | Message::BlocklistRequest { .. }
            | Message::BlocklistResponse { .. }
            | Message::BlocklistUpdate { .. }
            | Message::BlocklistWriteComplete { .. }
            | Message::PoisonImageResponse { .. }
            | Message::GetCompressedResponse { .. }
            | Message::UnifiedServerWorkerStarted { .. }
            | Message::UnifiedServerWorkerReady { .. }
            | Message::UnifiedServerWorkerHeartbeat { .. }
            | Message::UnifiedServerWorkerShutdownComplete { .. }
            | Message::UnifiedServerWorkerDrain { .. }
            | Message::UnifiedServerWorkerDrained { .. }
            | Message::UnifiedServerWorkerResize { .. }
            | Message::UnifiedServerWorkerResizeAck { .. }
            | Message::WorkerDrain { .. }
            | Message::WorkerDrained { .. }
            | Message::UpgradeReady { .. }
            | Message::SupervisorUpgradeCommit { .. }
            | Message::SupervisorDrainWorkers { .. }
            | Message::SupervisorDrainWorkersAck { .. }
            | Message::SupervisorGetStatus
            | Message::MasterDrainMode { .. }
            | Message::MasterDrainModeAck { .. }
            | Message::MasterReportConnections { .. }
            | Message::MasterConnectionsReport { .. }
            | Message::MasterStopAccepting { .. }
            | Message::MasterStopAcceptingAck { .. }
            | Message::WorkerConnectionCount { .. }
            | Message::WorkerDrainComplete { .. }
            | Message::SupervisorCommitUpgrade { .. }
            | Message::SocketHandoffReady { .. }
            | Message::SocketHandoffComplete { .. }
            | Message::WindowsSocketInfo { .. }
            | Message::DrainRequest { .. }
            | Message::DrainStatusRequest { .. }
            | Message::DrainStatusResponse { .. }
            | Message::DrainComplete { .. }
            | Message::StopAccepting { .. }
            | Message::StopAcceptingAck { .. }
            | Message::RestoreFromDrain
            | Message::RestoreFromDrainAck { .. }
            | Message::WorkerReadyForTraffic { .. }
            | Message::MasterDrainStatus { .. }
            | Message::RestartWorkerRequest { .. }
            | Message::RestartWorkerResponse { .. }
            | Message::CommandResponse { .. } => Ok(()),

            // Variants with string fields that need validation
            Message::WorkerError { error, .. } => {
                check_str("WorkerError.error", error, MAX_STRING_LENGTH)
            }
            Message::MasterConfigReload { config_path } => check_str(
                "MasterConfigReload.config_path",
                config_path,
                MAX_PATH_LENGTH,
            ),
            Message::CpuWorkerScan { site_id } => {
                check_str("CpuWorkerScan.site_id", site_id, MAX_STRING_LENGTH)
            }
            Message::CpuWorkerCacheUpdate {
                site_id,
                path,
                minified_path,
            } => {
                check_str(
                    "CpuWorkerCacheUpdate.site_id",
                    site_id,
                    MAX_STRING_LENGTH,
                )?;
                check_path_str("CpuWorkerCacheUpdate.path", path, MAX_PATH_LENGTH)?;
                check_path_str(
                    "CpuWorkerCacheUpdate.minified_path",
                    minified_path,
                    MAX_PATH_LENGTH,
                )
            }
            Message::UpstreamGlobalStats {
                worker_id: _,
                backend_stats,
            } => {
                for url in backend_stats.keys() {
                    check_str(
                        "UpstreamGlobalStats.backend_stats.url",
                        url,
                        MAX_PATH_LENGTH,
                    )?;
                }
                Ok(())
            }
            Message::GlobalUpstreamStatsBroadcast { aggregated_stats } => {
                for url in aggregated_stats.keys() {
                    check_str(
                        "GlobalUpstreamStatsBroadcast.aggregated_stats.url",
                        url,
                        MAX_PATH_LENGTH,
                    )?;
                }
                Ok(())
            }
            Message::ThreatIndicatorAnnounce {
                indicator_value,
                reason,
                site_scope,
                suspicious_pattern,
                ..
            } => {
                check_str("indicator_value", indicator_value, MAX_STRING_LENGTH)?;
                check_str("reason", reason, MAX_STRING_LENGTH)?;
                check_str("site_scope", site_scope, MAX_STRING_LENGTH)?;
                check_opt_str("suspicious_pattern", suspicious_pattern, MAX_STRING_LENGTH)
            }
            Message::ThreatIndicatorFromMesh {
                source_node_id,
                indicator_value,
                reason,
                site_scope,
                ..
            } => {
                check_str("source_node_id", source_node_id, MAX_STRING_LENGTH)?;
                check_str("indicator_value", indicator_value, MAX_STRING_LENGTH)?;
                check_str("reason", reason, MAX_STRING_LENGTH)?;
                check_str("site_scope", site_scope, MAX_STRING_LENGTH)
            }
            Message::ThreatFeedUpdate {
                indicators,
                version,
                timestamp,
            } => {
                check_str(
                    "ThreatFeedUpdate.version",
                    &version.to_string(),
                    MAX_STRING_LENGTH,
                )?;
                check_str(
                    "ThreatFeedUpdate.timestamp",
                    &timestamp.to_string(),
                    MAX_STRING_LENGTH,
                )?;
                for indicator in indicators {
                    check_str(
                        "indicator_value",
                        &indicator.indicator_value,
                        MAX_STRING_LENGTH,
                    )?;
                    check_str("reason", &indicator.reason, MAX_STRING_LENGTH)?;
                    check_str("site_scope", &indicator.site_scope, MAX_STRING_LENGTH)?;
                }
                Ok(())
            }
            Message::RulePatternsUpdate { version, patterns } => {
                check_str("version", version, MAX_STRING_LENGTH)?;
                for p in patterns {
                    check_str("pattern.category", &p.category, MAX_STRING_LENGTH)?;
                    check_str_vec("pattern.patterns", &p.patterns, MAX_STRING_LENGTH)?;
                }
                Ok(())
            }
            Message::MinifyRequest {
                site_id,
                path,
                encoding,
                ..
            } => {
                check_str("MinifyRequest.site_id", site_id, MAX_STRING_LENGTH)?;
                check_str("MinifyRequest.path", path, MAX_PATH_LENGTH)?;
                check_opt_str("MinifyRequest.encoding", encoding, MAX_STRING_LENGTH)
            }
            Message::MinifyResponse {
                site_id,
                path,
                content_type,
                encoding,
                queued_encodings,
                ..
            } => {
                check_str("MinifyResponse.site_id", site_id, MAX_STRING_LENGTH)?;
                check_str("MinifyResponse.path", path, MAX_PATH_LENGTH)?;
                check_str(
                    "MinifyResponse.content_type",
                    content_type,
                    MAX_STRING_LENGTH,
                )?;
                check_opt_str("MinifyResponse.encoding", encoding, MAX_STRING_LENGTH)?;
                check_str_vec(
                    "MinifyResponse.queued_encodings",
                    queued_encodings,
                    MAX_STRING_LENGTH,
                )
            }
            Message::MinifyError { error, .. } => {
                check_str("MinifyError.error", error, MAX_STRING_LENGTH)
            }
            Message::PoisonImageRequest {
                site_id,
                last_modified,
                ..
            } => {
                check_str("PoisonImageRequest.site_id", site_id, MAX_STRING_LENGTH)?;
                check_opt_str(
                    "PoisonImageRequest.last_modified",
                    last_modified,
                    MAX_STRING_LENGTH,
                )
            }
            Message::PoisonImageError { error, .. } => {
                check_str("PoisonImageError.error", error, MAX_STRING_LENGTH)
            }
            Message::GetCompressedRequest {
                site_id,
                path,
                encoding,
                ..
            } => {
                check_str("GetCompressedRequest.site_id", site_id, MAX_STRING_LENGTH)?;
                check_str("GetCompressedRequest.path", path, MAX_PATH_LENGTH)?;
                check_str("GetCompressedRequest.encoding", encoding, MAX_STRING_LENGTH)
            }
            Message::CpuTaskRequest {
                task_kind,
                payload_size_limit,
                output_size_limit,
                file_payload_path,
                payload,
                ..
            } => {
                check_opt_path_str(
                    "CpuTaskRequest.file_payload_path",
                    file_payload_path,
                    MAX_PATH_LENGTH,
                )?;
                check_str(
                    "CpuTaskRequest.payload_size_limit",
                    &payload_size_limit.to_string(),
                    MAX_STRING_LENGTH,
                )?;
                check_str(
                    "CpuTaskRequest.output_size_limit",
                    &output_size_limit.to_string(),
                    MAX_STRING_LENGTH,
                )?;
                if *task_kind != payload.task_kind() {
                    return Err(IpcValidationError {
                        field: "CpuTaskRequest.task_kind".into(),
                        message: format!(
                            "task_kind {:?} does not match payload {:?}",
                            task_kind,
                            payload.task_kind()
                        ),
                    });
                }
                match payload {
                    CpuTaskPayload::Minify {
                        site_id,
                        path,
                        encoding,
                    } => {
                        check_str("CpuTaskPayload.Minify.site_id", site_id, MAX_STRING_LENGTH)?;
                        check_str("CpuTaskPayload.Minify.path", path, MAX_PATH_LENGTH)?;
                        check_opt_str(
                            "CpuTaskPayload.Minify.encoding",
                            encoding,
                            MAX_STRING_LENGTH,
                        )
                    }
                    CpuTaskPayload::GetCompressed {
                        site_id,
                        path,
                        encoding,
                    } => {
                        check_str(
                            "CpuTaskPayload.GetCompressed.site_id",
                            site_id,
                            MAX_STRING_LENGTH,
                        )?;
                        check_str("CpuTaskPayload.GetCompressed.path", path, MAX_PATH_LENGTH)?;
                        check_str(
                            "CpuTaskPayload.GetCompressed.encoding",
                            encoding,
                            MAX_STRING_LENGTH,
                        )
                    }
                    CpuTaskPayload::PoisonImage {
                        site_id,
                        last_modified,
                        ..
                    } => {
                        check_str(
                            "CpuTaskPayload.PoisonImage.site_id",
                            site_id,
                            MAX_STRING_LENGTH,
                        )?;
                        check_opt_str(
                            "CpuTaskPayload.PoisonImage.last_modified",
                            last_modified,
                            MAX_STRING_LENGTH,
                        )
                    }
                    CpuTaskPayload::YaraScan {
                        site_id,
                        excluded_categories,
                        ..
                    } => {
                        check_str(
                            "CpuTaskPayload.YaraScan.site_id",
                            site_id,
                            MAX_STRING_LENGTH,
                        )?;
                        check_str_vec(
                            "CpuTaskPayload.YaraScan.excluded_categories",
                            excluded_categories,
                            MAX_STRING_LENGTH,
                        )
                    }
                    CpuTaskPayload::WasmExecute {
                        site_id,
                        plugin_name,
                        function_name,
                        input,
                        timeout_ms,
                    } => {
                        check_str(
                            "CpuTaskPayload.WasmExecute.site_id",
                            site_id,
                            MAX_STRING_LENGTH,
                        )?;
                        check_str(
                            "CpuTaskPayload.WasmExecute.plugin_name",
                            plugin_name,
                            MAX_STRING_LENGTH,
                        )?;
                        check_str(
                            "CpuTaskPayload.WasmExecute.function_name",
                            function_name,
                            MAX_STRING_LENGTH,
                        )?;
                        if input.len() > MAX_STRING_LENGTH {
                            return Err(IpcValidationError {
                                field: "CpuTaskPayload.WasmExecute.input".into(),
                                message: format!("{} > {}", input.len(), MAX_STRING_LENGTH),
                            });
                        }
                        if *timeout_ms == 0 {
                            return Err(IpcValidationError {
                                field: "CpuTaskPayload.WasmExecute.timeout_ms".into(),
                                message: "timeout_ms must be > 0".into(),
                            });
                        }
                        Ok(())
                    }
                    CpuTaskPayload::ServerlessInvoke {
                        site_id,
                        function_name,
                        input,
                        timeout_ms,
                    } => {
                        check_str(
                            "CpuTaskPayload.ServerlessInvoke.site_id",
                            site_id,
                            MAX_STRING_LENGTH,
                        )?;
                        check_str(
                            "CpuTaskPayload.ServerlessInvoke.function_name",
                            function_name,
                            MAX_STRING_LENGTH,
                        )?;
                        if input.len() > MAX_STRING_LENGTH {
                            return Err(IpcValidationError {
                                field: "CpuTaskPayload.ServerlessInvoke.input".into(),
                                message: format!("{} > {}", input.len(), MAX_STRING_LENGTH),
                            });
                        }
                        if *timeout_ms == 0 {
                            return Err(IpcValidationError {
                                field: "CpuTaskPayload.ServerlessInvoke.timeout_ms".into(),
                                message: "timeout_ms must be > 0".into(),
                            });
                        }
                        Ok(())
                    }
                }
            }
            Message::CpuTaskCancel { .. } => Ok(()),
            Message::CpuTaskError { message, .. } => {
                check_str("CpuTaskError.message", message, MAX_STRING_LENGTH)
            }
            Message::CpuTaskResponse {
                task_kind, result, ..
            } => {
                if *task_kind != result.task_kind() {
                    return Err(IpcValidationError {
                        field: "CpuTaskResponse.task_kind".into(),
                        message: format!(
                            "task_kind {:?} does not match result {:?}",
                            task_kind,
                            result.task_kind()
                        ),
                    });
                }
                match result {
                    CpuTaskResult::Minify {
                        site_id,
                        path,
                        content_type,
                        encoding,
                        queued_encodings,
                        ..
                    } => {
                        check_str("CpuTaskResult.Minify.site_id", site_id, MAX_STRING_LENGTH)?;
                        check_str("CpuTaskResult.Minify.path", path, MAX_PATH_LENGTH)?;
                        check_str(
                            "CpuTaskResult.Minify.content_type",
                            content_type,
                            MAX_STRING_LENGTH,
                        )?;
                        check_opt_str(
                            "CpuTaskResult.Minify.encoding",
                            encoding,
                            MAX_STRING_LENGTH,
                        )?;
                        check_str_vec(
                            "CpuTaskResult.Minify.queued_encodings",
                            queued_encodings,
                            MAX_STRING_LENGTH,
                        )
                    }
                    CpuTaskResult::GetCompressed { .. } => Ok(()),
                    CpuTaskResult::PoisonImage { .. } => Ok(()),
                    CpuTaskResult::YaraScan { matches } => {
                        check_str_vec("CpuTaskResult.YaraScan.matches", matches, MAX_STRING_LENGTH)
                    }
                    CpuTaskResult::WasmExecute { output } => {
                        if output.len() > MAX_STRING_LENGTH {
                            return Err(IpcValidationError {
                                field: "CpuTaskResult.WasmExecute.output".into(),
                                message: format!("{} > {}", output.len(), MAX_STRING_LENGTH),
                            });
                        }
                        Ok(())
                    }
                    CpuTaskResult::ServerlessInvoke { output } => {
                        if output.len() > MAX_STRING_LENGTH {
                            return Err(IpcValidationError {
                                field: "CpuTaskResult.ServerlessInvoke.output".into(),
                                message: format!("{} > {}", output.len(), MAX_STRING_LENGTH),
                            });
                        }
                        Ok(())
                    }
                }
            }
            Message::AppServerStarted {
                site_id,
                socket_path,
                ..
            } => {
                check_str("AppServerStarted.site_id", site_id, MAX_STRING_LENGTH)?;
                check_opt_path_str("AppServerStarted.socket_path", socket_path, MAX_PATH_LENGTH)
            }
            Message::AppServerReady { site_id, .. } => {
                check_str("AppServerReady.site_id", site_id, MAX_STRING_LENGTH)
            }
            Message::AppServerHealth { site_id, .. } => {
                check_str("AppServerHealth.site_id", site_id, MAX_STRING_LENGTH)
            }
            Message::AppServerStopped { site_id, .. } => {
                check_str("AppServerStopped.site_id", site_id, MAX_STRING_LENGTH)
            }
            Message::AppServerRestarted { site_id, .. } => {
                check_str("AppServerRestarted.site_id", site_id, MAX_STRING_LENGTH)
            }
            Message::AppServerError { site_id, error, .. } => {
                check_str("AppServerError.site_id", site_id, MAX_STRING_LENGTH)?;
                check_str("AppServerError.error", error, MAX_STRING_LENGTH)
            }
            Message::UnifiedServerWorkerError { error, .. } => {
                check_str("UnifiedServerWorkerError.error", error, MAX_STRING_LENGTH)
            }
            Message::WorkerRequestLog { log, .. } | Message::CpuWorkerRequestLog { log, .. } => {
                check_str(
                    "RequestLogPayload.client_ip",
                    &log.client_ip,
                    MAX_STRING_LENGTH,
                )?;
                check_str("RequestLogPayload.method", &log.method, MAX_STRING_LENGTH)?;
                check_str("RequestLogPayload.path", &log.path, MAX_STRING_LENGTH)?;
                check_str("RequestLogPayload.site_id", &log.site_id, MAX_STRING_LENGTH)?;
                check_opt_str(
                    "RequestLogPayload.user_agent",
                    &log.user_agent,
                    MAX_STRING_LENGTH,
                )
            }
            Message::UpgradeFailed { error } => {
                check_str("UpgradeFailed.error", error, MAX_STRING_LENGTH)
            }
            Message::SupervisorUpgradePrepare {
                binary_path,
                config_path,
                version,
            } => {
                check_path_str("binary_path", binary_path, MAX_PATH_LENGTH)?;
                check_opt_path_str("config_path", config_path, MAX_PATH_LENGTH)?;
                check_str("version", version, MAX_STRING_LENGTH)
            }
            Message::SupervisorUpgradePrepareAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::SupervisorUpgradeCommitAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::SupervisorUpgradeRollback { reason } => {
                check_str("reason", reason, MAX_STRING_LENGTH)
            }
            Message::SupervisorUpgradeRollbackAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::SupervisorStatusResponse { version, .. } => {
                check_str("version", version, MAX_STRING_LENGTH)
            }
            Message::SupervisorDualSupervisorPrepare {
                binary_path,
                config_path,
                version,
            } => {
                check_path_str("binary_path", binary_path, MAX_PATH_LENGTH)?;
                check_opt_path_str("config_path", config_path, MAX_PATH_LENGTH)?;
                check_str("version", version, MAX_STRING_LENGTH)
            }
            Message::SupervisorDualSupervisorPrepareAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::SupervisorCommitUpgradeAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::SocketHandoffRequest { socket_path } => {
                check_path_str("socket_path", socket_path, MAX_PATH_LENGTH)
            }
            Message::SocketHandoffFailed { error } => check_str("error", error, MAX_STRING_LENGTH),
            Message::SocketHandoffActiveConnection {
                protocol,
                client_addr,
                ..
            } => {
                check_str("protocol", protocol, MAX_STRING_LENGTH)?;
                check_str("client_addr", client_addr, MAX_STRING_LENGTH)
            }
            Message::WorkerConnectionHandoff {
                protocol,
                client_addr,
                ..
            } => {
                check_str("protocol", protocol, MAX_STRING_LENGTH)?;
                check_str("client_addr", client_addr, MAX_STRING_LENGTH)
            }
            Message::WorkerConnectionAdopted { .. } => Ok(()),
            Message::PluginStateSync { plugin_name, .. } => check_str(
                "PluginStateSync.plugin_name",
                plugin_name,
                MAX_STRING_LENGTH,
            ),
            Message::PluginExecuteRequest(req) => {
                check_str(
                    "PluginExecuteRequest.plugin_name",
                    &req.plugin_name,
                    MAX_STRING_LENGTH,
                )?;
                check_str(
                    "PluginExecuteRequest.function_name",
                    &req.function_name,
                    MAX_STRING_LENGTH,
                )?;
                for (k, v) in &req.headers {
                    check_str("PluginExecuteRequest.headers.key", k, MAX_STRING_LENGTH)?;
                    check_str("PluginExecuteRequest.headers.value", v, MAX_STRING_LENGTH)?;
                }
                Ok(())
            }
            Message::PluginExecuteResponse(res) => {
                for (k, v) in &res.headers {
                    check_str("PluginExecuteResponse.headers.key", k, MAX_STRING_LENGTH)?;
                    check_str("PluginExecuteResponse.headers.value", v, MAX_STRING_LENGTH)?;
                }
                check_opt_str("PluginExecuteResponse.error", &res.error, MAX_STRING_LENGTH)
            }
            Message::ServerlessHandleRequest(req) => {
                check_str(
                    "ServerlessHandleRequest.function_name",
                    &req.function_name,
                    MAX_STRING_LENGTH,
                )?;
                for (k, v) in &req.headers {
                    check_str("ServerlessHandleRequest.headers.key", k, MAX_STRING_LENGTH)?;
                    check_str(
                        "ServerlessHandleRequest.headers.value",
                        v,
                        MAX_STRING_LENGTH,
                    )?;
                }
                for (k, v) in &req.env_vars {
                    check_str("ServerlessHandleRequest.env_vars.key", k, MAX_STRING_LENGTH)?;
                    check_str(
                        "ServerlessHandleRequest.env_vars.value",
                        v,
                        MAX_STRING_LENGTH,
                    )?;
                }
                Ok(())
            }
            Message::ServerlessHandleResponse(res) => {
                for (k, v) in &res.headers {
                    check_str("ServerlessHandleResponse.headers.key", k, MAX_STRING_LENGTH)?;
                    check_str(
                        "ServerlessHandleResponse.headers.value",
                        v,
                        MAX_STRING_LENGTH,
                    )?;
                }
                check_opt_str(
                    "ServerlessHandleResponse.error",
                    &res.error,
                    MAX_STRING_LENGTH,
                )
            }
            Message::StreamChunk { chunk, .. } => check_str(
                "StreamChunk.chunk",
                &format!("{}", chunk.len()),
                MAX_STRING_LENGTH,
            ),
            Message::MeshControlRequest { request, .. } => match request {
                MeshControlRequest::DhtLookup { key } => {
                    check_str("MeshControlRequest.DhtLookup.key", key, MAX_STRING_LENGTH)
                }
                MeshControlRequest::PeerRegister { node_id, address } => {
                    check_str(
                        "MeshControlRequest.PeerRegister.node_id",
                        node_id,
                        MAX_STRING_LENGTH,
                    )?;
                    check_str(
                        "MeshControlRequest.PeerRegister.address",
                        address,
                        MAX_STRING_LENGTH,
                    )
                }
                MeshControlRequest::RaftStatus => Ok(()),
            },
            Message::MeshControlResponse { response, .. } => match response {
                MeshControlResponse::DhtValue { key, .. } => {
                    check_str("MeshControlResponse.DhtValue.key", key, MAX_STRING_LENGTH)
                }
                MeshControlResponse::RaftStatus { leader_id, .. } => check_opt_str(
                    "MeshControlResponse.RaftStatus.leader_id",
                    leader_id,
                    MAX_STRING_LENGTH,
                ),
                MeshControlResponse::PeerRegistered { .. } => Ok(()),
                MeshControlResponse::Error { message } => check_str(
                    "MeshControlResponse.Error.message",
                    message,
                    MAX_STRING_LENGTH,
                ),
            },
            Message::MeshUpdateNotification { notification, .. } => match notification {
                MeshUpdateNotification::PeerJoined { node_id, address } => {
                    check_str(
                        "MeshUpdateNotification.PeerJoined.node_id",
                        node_id,
                        MAX_STRING_LENGTH,
                    )?;
                    check_str(
                        "MeshUpdateNotification.PeerJoined.address",
                        address,
                        MAX_STRING_LENGTH,
                    )
                }
                MeshUpdateNotification::PeerLeft { node_id } => check_str(
                    "MeshUpdateNotification.PeerLeft.node_id",
                    node_id,
                    MAX_STRING_LENGTH,
                ),
                MeshUpdateNotification::DhtKeyUpdated { key } => check_str(
                    "MeshUpdateNotification.DhtKeyUpdated.key",
                    key,
                    MAX_STRING_LENGTH,
                ),
            }, // NOTE: Do NOT add a catch-all here. All variants must be explicitly handled
               // so that adding a new Message variant causes a compile-time error.
        }
    }

    /// Returns the concern group this message belongs to.
    pub fn category(&self) -> MessageCategory {
        match self {
            Message::WorkerStarted { .. }
            | Message::WorkerReady { .. }
            | Message::WorkerHeartbeat { .. }
            | Message::WorkerRequestLog { .. }
            | Message::WorkerShutdownComplete { .. }
            | Message::WorkerError { .. }
            | Message::WorkerCertReload { .. } => MessageCategory::WorkerLifecycle,

            Message::MasterShutdown { .. }
            | Message::MasterConfigReload { .. }
            | Message::MasterProcessConfigReload { .. }
            | Message::MasterSupervisorConfigReload { .. }
            | Message::MasterHealthCheck { .. }
            | Message::MasterResizeThreadpool { .. }
            | Message::MasterCertReload
            | Message::HealthCheckAck { .. }
            | Message::WorkerResizeAck { .. } => MessageCategory::SupervisorCommand,

            Message::CpuWorkerStarted { .. }
            | Message::CpuWorkerReady { .. }
            | Message::CpuWorkerHeartbeat { .. }
            | Message::CpuWorkerRequestLog { .. }
            | Message::CpuWorkerShutdownComplete { .. }
            | Message::CpuWorkerBackgroundTasksDone { .. }
            | Message::CpuWorkerResizeAck { .. }
            | Message::CpuWorkerScan { .. }
            | Message::CpuWorkerCacheUpdate { .. }
            | Message::CpuWorkerDrain { .. }
            | Message::CpuWorkerDrained { .. }
            | Message::CpuWorkerDrainStatus { .. } => MessageCategory::CpuWorker,

            Message::UpstreamGlobalStats { .. } | Message::GlobalUpstreamStatsBroadcast { .. } => {
                MessageCategory::Upstream
            }

            Message::ThreatIndicatorAnnounce { .. }
            | Message::ThreatIndicatorFromMesh { .. }
            | Message::ThreatSyncRequest { .. }
            | Message::ThreatSyncResponse { .. }
            | Message::ThreatFeedUpdate { .. }
            | Message::BlocklistRequest { .. }
            | Message::BlocklistResponse { .. } => MessageCategory::ThreatIntel,

            Message::BlocklistUpdate { .. }
            | Message::RulePatternsUpdate { .. }
            | Message::BlocklistWriteComplete { .. } => MessageCategory::BlocklistRules,

            Message::MinifyRequest { .. }
            | Message::MinifyResponse { .. }
            | Message::MinifyError { .. }
            | Message::PoisonImageRequest { .. }
            | Message::PoisonImageResponse { .. }
            | Message::PoisonImageError { .. }
            | Message::GetCompressedRequest { .. }
            | Message::GetCompressedResponse { .. }
            | Message::CpuTaskRequest { .. }
            | Message::CpuTaskCancel { .. }
            | Message::CpuTaskResponse { .. }
            | Message::CpuTaskError { .. } => MessageCategory::CpuWorker,

            Message::AppServerStarted { .. }
            | Message::AppServerReady { .. }
            | Message::AppServerHealth { .. }
            | Message::AppServerStopped { .. }
            | Message::AppServerRestarted { .. }
            | Message::AppServerError { .. } => MessageCategory::AppServer,

            Message::UnifiedServerWorkerStarted { .. }
            | Message::UnifiedServerWorkerReady { .. }
            | Message::UnifiedServerWorkerHeartbeat { .. }
            | Message::UnifiedServerWorkerShutdownComplete { .. }
            | Message::UnifiedServerWorkerError { .. }
            | Message::UnifiedServerWorkerDrain { .. }
            | Message::UnifiedServerWorkerDrained { .. }
            | Message::UnifiedServerWorkerResize { .. }
            | Message::UnifiedServerWorkerResizeAck { .. } => MessageCategory::UnifiedServer,

            Message::WorkerDrain { .. }
            | Message::WorkerDrained { .. }
            | Message::WorkerConnectionCount { .. }
            | Message::WorkerDrainComplete { .. }
            | Message::WorkerReadyForTraffic { .. } => MessageCategory::WorkerDrain,

            Message::UpgradeReady { .. }
            | Message::UpgradeFailed { .. }
            | Message::SupervisorUpgradePrepare { .. }
            | Message::SupervisorUpgradePrepareAck { .. }
            | Message::SupervisorUpgradeCommit { .. }
            | Message::SupervisorUpgradeCommitAck { .. }
            | Message::SupervisorUpgradeRollback { .. }
            | Message::SupervisorUpgradeRollbackAck { .. }
            | Message::SupervisorCommitUpgrade { .. }
            | Message::SupervisorCommitUpgradeAck { .. } => MessageCategory::Upgrade,

            Message::SupervisorDrainWorkers { .. }
            | Message::SupervisorDrainWorkersAck { .. }
            | Message::SupervisorGetStatus
            | Message::SupervisorStatusResponse { .. }
            | Message::SupervisorDualSupervisorPrepare { .. }
            | Message::SupervisorDualSupervisorPrepareAck { .. } => MessageCategory::Supervisor,

            Message::MasterDrainMode { .. }
            | Message::MasterDrainModeAck { .. }
            | Message::MasterReportConnections { .. }
            | Message::MasterConnectionsReport { .. }
            | Message::MasterStopAccepting { .. }
            | Message::MasterStopAcceptingAck { .. }
            | Message::MasterDrainStatus { .. } => MessageCategory::MasterDrain,

            Message::DrainRequest { .. }
            | Message::DrainStatusRequest { .. }
            | Message::DrainStatusResponse { .. }
            | Message::DrainComplete { .. }
            | Message::StopAccepting { .. }
            | Message::StopAcceptingAck { .. }
            | Message::RestoreFromDrain
            | Message::RestoreFromDrainAck { .. } => MessageCategory::DrainProtocol,

            Message::SocketHandoffRequest { .. }
            | Message::SocketHandoffReady { .. }
            | Message::SocketHandoffComplete { .. }
            | Message::SocketHandoffFailed { .. }
            | Message::SocketHandoffActiveConnection { .. }
            | Message::WorkerConnectionHandoff { .. }
            | Message::WorkerConnectionAdopted { .. }
            | Message::WindowsSocketInfo { .. } => MessageCategory::SocketHandoff,

            Message::RestartWorkerRequest { .. } | Message::RestartWorkerResponse { .. } => {
                MessageCategory::WorkerRestart
            }

            Message::StreamChunk { .. } => MessageCategory::UnifiedServer,
            Message::CommandResponse { .. } => MessageCategory::SupervisorCommand,

            Message::PluginStateSync { .. }
            | Message::PluginExecuteRequest(_)
            | Message::PluginExecuteResponse(_)
            | Message::ServerlessHandleRequest(_)
            | Message::ServerlessHandleResponse(_) => MessageCategory::Plugin,

            Message::MeshControlRequest { .. }
            | Message::MeshControlResponse { .. }
            | Message::MeshUpdateNotification { .. } => MessageCategory::MeshControl,
        }
    }

    /// Returns true if this message is a lifecycle message (started, ready, heartbeat, shutdown).
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self.category(),
            MessageCategory::WorkerLifecycle
                | MessageCategory::CpuWorker
                | MessageCategory::UnifiedServer
                | MessageCategory::AppServer
        )
    }

    /// Returns true if this message is a drain-related message.
    pub fn is_drain(&self) -> bool {
        matches!(
            self.category(),
            MessageCategory::WorkerDrain
                | MessageCategory::MasterDrain
                | MessageCategory::DrainProtocol
        )
    }

    /// Converts a legacy static-content request into the generic CPU worker task envelope.
    ///
    /// Returns `(request, is_legacy_shape)` where `is_legacy_shape` indicates
    /// that the original message used one of the legacy `*Request` variants.
    pub fn into_cpu_task_request_compat(
        self,
    ) -> Option<(
        u64,
        CpuTaskKind,
        CpuTaskPriority,
        CpuTaskPolicy,
        u64,
        u64,
        u64,
        Option<String>,
        CpuTaskPayload,
        bool,
    )> {
        match self {
            Message::CpuTaskRequest {
                request_id,
                task_kind,
                priority,
                policy,
                deadline_unix_ms,
                payload_size_limit,
                output_size_limit,
                file_payload_path,
                payload,
            } => Some((
                request_id,
                task_kind,
                priority,
                policy,
                deadline_unix_ms,
                payload_size_limit,
                output_size_limit,
                file_payload_path,
                payload,
                false,
            )),
            Message::MinifyRequest {
                request_id,
                site_id,
                path,
                encoding,
            } => Some((
                request_id,
                CpuTaskKind::Minify,
                CpuTaskPriority::Normal,
                CpuTaskPolicy::SkipTransform,
                0,
                u64::MAX,
                u64::MAX,
                None,
                CpuTaskPayload::Minify {
                    site_id,
                    path,
                    encoding,
                },
                true,
            )),
            Message::GetCompressedRequest {
                request_id,
                site_id,
                path,
                encoding,
            } => Some((
                request_id,
                CpuTaskKind::GetCompressed,
                CpuTaskPriority::Normal,
                CpuTaskPolicy::SkipTransform,
                0,
                u64::MAX,
                u64::MAX,
                None,
                CpuTaskPayload::GetCompressed {
                    site_id,
                    path,
                    encoding,
                },
                true,
            )),
            Message::PoisonImageRequest {
                request_id,
                site_id,
                body,
                last_modified,
                level,
                intensity,
                seed,
                max_dimension,
                jpeg_quality,
            } => Some((
                request_id,
                CpuTaskKind::PoisonImage,
                CpuTaskPriority::Normal,
                CpuTaskPolicy::DegradeToInlineSmallOnly,
                0,
                u64::MAX,
                u64::MAX,
                None,
                CpuTaskPayload::PoisonImage {
                    site_id,
                    body,
                    last_modified,
                    level,
                    intensity,
                    seed,
                    max_dimension,
                    jpeg_quality,
                },
                true,
            )),
            _ => None,
        }
    }

    /// Adapts a generic CPU task response back to the legacy static-content
    /// response variants when `is_legacy_shape` is true.
    pub fn adapt_cpu_task_response_compat(
        response: Message,
        request_id: u64,
        task_kind: CpuTaskKind,
        is_legacy_shape: bool,
    ) -> Message {
        if !is_legacy_shape {
            return response;
        }

        match response {
            Message::CpuTaskResponse { result, .. } => match (task_kind, result) {
                (
                    CpuTaskKind::Minify,
                    CpuTaskResult::Minify {
                        site_id,
                        path,
                        content,
                        content_type,
                        encoding,
                        queued_encodings,
                    },
                ) => Message::MinifyResponse {
                    request_id,
                    site_id,
                    path,
                    content,
                    content_type,
                    encoding,
                    queued_encodings,
                },
                (CpuTaskKind::GetCompressed, CpuTaskResult::GetCompressed { content }) => {
                    Message::GetCompressedResponse {
                        request_id,
                        content,
                    }
                }
                (CpuTaskKind::PoisonImage, CpuTaskResult::PoisonImage { poisoned_body }) => {
                    Message::PoisonImageResponse {
                        request_id,
                        poisoned_body,
                    }
                }
                (_, _) => Message::MinifyError {
                    request_id,
                    error: "CPU task result kind mismatch".to_string(),
                },
            },
            Message::CpuTaskError { message, .. } => match task_kind {
                CpuTaskKind::PoisonImage => Message::PoisonImageError {
                    request_id,
                    error: message,
                },
                _ => Message::MinifyError {
                    request_id,
                    error: message,
                },
            },
            other => other,
        }
    }
}

/// IPC Message concern groups for logical organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCategory {
    WorkerLifecycle,
    SupervisorCommand,
    CpuWorker,
    ThreatIntel,
    BlocklistRules,
    StaticContent,
    AppServer,
    UnifiedServer,
    WorkerDrain,
    Upgrade,
    Supervisor,
    MasterDrain,
    DrainProtocol,
    SocketHandoff,
    WorkerRestart,
    Plugin,
    MeshControl,
    Upstream,
}

impl std::fmt::Display for MessageCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageCategory::WorkerLifecycle => write!(f, "WorkerLifecycle"),
            MessageCategory::SupervisorCommand => write!(f, "SupervisorCommand"),
            MessageCategory::CpuWorker => write!(f, "CpuWorker"),
            MessageCategory::ThreatIntel => write!(f, "ThreatIntel"),
            MessageCategory::BlocklistRules => write!(f, "BlocklistRules"),
            MessageCategory::StaticContent => write!(f, "StaticContent"),
            MessageCategory::AppServer => write!(f, "AppServer"),
            MessageCategory::UnifiedServer => write!(f, "UnifiedServer"),
            MessageCategory::WorkerDrain => write!(f, "WorkerDrain"),
            MessageCategory::Upgrade => write!(f, "Upgrade"),
            MessageCategory::Supervisor => write!(f, "Supervisor"),
            MessageCategory::MasterDrain => write!(f, "MasterDrain"),
            MessageCategory::DrainProtocol => write!(f, "DrainProtocol"),
            MessageCategory::SocketHandoff => write!(f, "SocketHandoff"),
            MessageCategory::WorkerRestart => write!(f, "WorkerRestart"),
            MessageCategory::Plugin => write!(f, "Plugin"),
            MessageCategory::MeshControl => write!(f, "MeshControl"),
            MessageCategory::Upstream => write!(f, "Upstream"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeModePayload {
    ReusePort,
    PortSwap { temp_port_offset: u16 },
}

pub use crate::metrics::{RequestLogPayload, SiteMetricsPayload, WorkerMetricsPayload};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    Starting,
    Ready,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// Synchronous IPC stream for framed message passing.
///
/// **COMPATIBILITY WARNING:** This is a legacy sync wrapper retained for
/// `std::thread::spawn` contexts (static worker connections, supervisor IPC
/// client) where tokio is not available. **New code should use
/// [`crate::process::ipc_transport::IpcStream`] (the async transport) which
/// supports message signing, `enforce_signing`, and proper framed I/O.**
///
/// This is a blocking wrapper around `UnixStream` (Unix) or `std::fs::File`
/// (Windows named pipe) that provides length-prefixed framing via
/// `send()` and `try_recv()`.
///
/// # Sync vs Async IpcStream
///
/// There are two IpcStream types with intentionally different APIs:
///
/// | Aspect | `ipc::IpcStream` (this) | `ipc_transport::IpcStream` |
/// |--------|------------------------|---------------------------|
/// | Runtime | Synchronous (std) | Async (tokio) |
/// | Unix inner | `std::os::unix::net::UnixStream` | `tokio::net::UnixStream` |
/// | Windows inner | `std::fs::File` | `tokio::net::windows::named_pipe::NamedPipeClient` |
/// | Message signing | Partial (via `send_signed`) | Full (via `IpcSigner`, `enforce_signing`) |
/// | Recv with timeout | Polling via `recv()` | Native `recv_with_timeout()` |
/// | AsyncRead/Write | No | Yes |
/// | Use case | Static worker threads, command handling | Supervisor↔Worker IPC, mesh transport |
///
/// The sync version is used from `std::thread::spawn` contexts (static worker
/// connections) where tokio is not available. The async version is used from
/// tokio tasks for the main worker IPC channel. Unifying these behind a single
/// trait would add complexity without clear benefit, since the use sites have
/// fundamentally different runtime constraints.
pub struct IpcStream {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    stream: std::fs::File,
    read_buffer: Vec<u8>,
    signer: Option<Arc<IpcSigner>>,
}

#[cfg(windows)]
pub struct WindowsIpcListener {
    pipe_path: String,
}

#[cfg(windows)]
impl WindowsIpcListener {
    pub fn new(pipe_name: &str) -> Self {
        Self {
            pipe_path: format!("\\\\.\\pipe\\{}", pipe_name),
        }
    }

    pub fn bind(&self) -> io::Result<()> {
        use windows_sys::Win32::Foundation::FILE_FLAG_OVERLAPPED;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
        use windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE;
        use windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE;
        use windows_sys::Win32::System::Pipes::PIPE_WAIT;

        let pipe_name: Vec<u16> = self
            .pipe_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: CreateNamedPipeW is called with a valid pipe name; we check for zero handle.
        unsafe {
            let handle: HANDLE = CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            );

            if handle == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn path(&self) -> &str {
        &self.pipe_path
    }

    /// Create a new named pipe instance and wait for a client connection.
    ///
    /// Returns a `File` handle representing the connected pipe. On failure,
    /// returns an error after logging. The caller owns the returned handle
    /// and is responsible for closing it.
    ///
    /// This implements the Windows named pipe accept pattern:
    /// 1. CreateNamedPipeW — create pipe instance
    /// 2. ConnectNamedPipe — wait for client
    /// 3. Convert to File for Rust I/O
    pub fn accept(&self) -> io::Result<std::fs::File> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(&self.pipe_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: CreateNamedPipeW is called with a valid UTF-16 pipe name
        // and correct pipe type/access flags. The handle is checked for zero.
        let pipe_handle = unsafe {
            windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                pipe_name_wide.as_ptr(),
                windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            )
        };

        if pipe_handle == 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: ConnectNamedPipe is called on a valid pipe handle.
        // The handle remains valid until we either return it or close it.
        let connected = unsafe {
            windows_sys::Win32::System::Pipes::ConnectNamedPipe(pipe_handle, std::ptr::null_mut())
        };

        if connected == 0 {
            // SAFETY: GetLastError returns thread-local error code.
            let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                // SAFETY: CloseHandle on valid handle we own on error path.
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(pipe_handle);
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }

        // SAFETY: from_raw_handle takes ownership of the valid, connected pipe handle.
        // No other code will use this handle after this transfer of ownership.
        Ok(unsafe {
            std::fs::File::from_raw_handle(pipe_handle as std::os::windows::io::RawHandle)
        })
    }
}

pub fn get_ipc_path(socket_path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        socket_path.to_string_lossy().to_string()
    }

    #[cfg(windows)]
    {
        let pipe_name = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("synvoid-supervisor");
        format!("\\\\.\\pipe\\{}", pipe_name)
    }
}

pub fn get_platform_info() -> crate::platform::Platform {
    crate::platform::platform()
}

/// Connect to the supervisor IPC endpoint without message signing.
///
/// **DEPRECATED:** Prefer [`crate::process::ipc_transport::connect_to_supervisor_signed`]
/// or [`crate::process::ipc_transport::IpcEndpoint::connect_with_signer`] for
/// production deployments. Unsigned connections must not be used for privileged
/// operations (Stop, ReloadConfig, threat data exchange).
pub fn connect_to_supervisor(path: &std::path::Path) -> io::Result<IpcStream> {
    #[cfg(unix)]
    {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true).ok();
        Ok(IpcStream {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
        })
    }

    #[cfg(windows)]
    {
        let pipe_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("synvoid-supervisor");
        let pipe_path = format!("\\\\.\\pipe\\{}", pipe_name);

        let mut attempts = 0;
        let max_attempts = 10;

        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_path)
            {
                Ok(handle) => {
                    return Ok(IpcStream {
                        stream: handle,
                        read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
                        signer: None,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl IpcStream {
    /// Create a new sync IpcStream from an existing Unix stream.
    ///
    /// **COMPATIBILITY:** Prefer using the async transport when possible.
    /// This constructor creates an unsigned stream; use `connect_with_signer`
    /// when message authentication is required.
    #[cfg(unix)]
    pub fn new(stream: UnixStream) -> Self {
        stream.set_nonblocking(true).ok();
        Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
        }
    }

    /// Create a new sync IpcStream from an existing Windows named pipe handle.
    ///
    /// **COMPATIBILITY:** Prefer using the async transport when possible.
    /// This constructor creates an unsigned stream.
    #[cfg(windows)]
    pub fn new(stream: std::fs::File) -> Self {
        Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
        }
    }

    /// Connect to a Unix socket with an IPC signer for message authentication.
    ///
    /// This is the preferred sync constructor when signing is required.
    #[cfg(unix)]
    pub fn connect_with_signer(path: &std::path::Path, signer: Arc<IpcSigner>) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true).ok();
        Ok(Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: Some(signer),
        })
    }

    /// Connect to a Unix socket without signing.
    ///
    /// **DEPRECATED for privileged paths:** Use `connect_with_signer` instead
    /// when the connection will carry privileged operations.
    #[cfg(unix)]
    pub fn connect_unix(path: &std::path::Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true).ok();
        Ok(Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            signer: None,
        })
    }

    /// Connect to the supervisor IPC endpoint without signing (Windows).
    ///
    /// **DEPRECATED for privileged paths:** Use the async transport with
    /// `connect_with_signer` when the connection will carry privileged operations.
    #[cfg(windows)]
    pub fn connect_unix(path: &std::path::Path) -> io::Result<Self> {
        connect_to_supervisor(path)
    }

    pub fn send(&mut self, msg: &Message) -> io::Result<()> {
        write_message_sync(&mut self.stream, msg)
    }

    pub fn send_signed(&mut self, msg: &Message) -> io::Result<()> {
        if let Some(ref signer) = self.signer {
            let data = SignedIpcMessage::serialize_signed(msg, signer)?;
            self.stream.write_all(&data)
        } else {
            write_message_sync(&mut self.stream, msg)
        }
    }

    pub fn try_recv(&mut self) -> io::Result<Option<Message>> {
        read_message_sync(&mut self.stream, &mut self.read_buffer)
    }

    pub fn try_recv_signed(&mut self) -> io::Result<Option<Message>> {
        if let Some(ref signer) = self.signer {
            SignedIpcMessage::deserialize_signed_from_stream(&mut self.stream, signer)
        } else {
            read_message_sync(&mut self.stream, &mut self.read_buffer)
        }
    }

    pub fn recv(&mut self, timeout_ms: u64) -> io::Result<Option<Message>> {
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        let mut sleep_duration = 1u64;
        let max_sleep = 50u64;

        loop {
            match self.try_recv_signed() {
                Ok(Some(msg)) => return Ok(Some(msg)),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    let jitter = rand::rng().random_range(0..sleep_duration / 2 + 1);
                    std::thread::sleep(Duration::from_millis(sleep_duration + jitter));
                    sleep_duration = (sleep_duration * 2).min(max_sleep);
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(unix)]
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }

    #[cfg(windows)]
    pub fn into_inner(self) -> std::fs::File {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_id() {
        let id = WorkerId(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_worker_id_clone() {
        let id = WorkerId(42);
        let cloned = id.clone();
        assert_eq!(id.0, cloned.0);
    }

    #[test]
    fn test_worker_id_debug() {
        let id = WorkerId(42);
        let debug = format!("{:?}", id);
        assert!(debug.contains("42"));
    }

    #[test]
    fn test_error_code_variants() {
        let codes = [
            ErrorCode::WorkerPanic,
            ErrorCode::Timeout,
            ErrorCode::ConfigLoadFailed,
            ErrorCode::SocketBindFailed,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let decoded: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, decoded);
        }
    }

    #[test]
    fn test_error_code_display() {
        let displays = [
            (ErrorCode::Unknown, "unknown"),
            (ErrorCode::WorkerPanic, "worker_panic"),
            (ErrorCode::Timeout, "timeout"),
        ];
        for (code, expected) in displays {
            assert_eq!(format!("{}", code), expected);
        }
    }

    #[test]
    fn test_error_severity_variants() {
        let severities = [
            ErrorSeverity::Warning,
            ErrorSeverity::Error,
            ErrorSeverity::Critical,
        ];
        for sev in severities {
            let json = serde_json::to_string(&sev).unwrap();
            let decoded: ErrorSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, decoded);
        }
    }

    #[test]
    fn test_error_severity_display() {
        let displays = [
            (ErrorSeverity::Warning, "warning"),
            (ErrorSeverity::Error, "error"),
            (ErrorSeverity::Critical, "critical"),
        ];
        for (sev, expected) in displays {
            assert_eq!(format!("{}", sev), expected);
        }
    }

    #[test]
    fn test_threat_indicator_type_variants() {
        let types = [
            ThreatIndicatorType::IpBlock,
            ThreatIndicatorType::RateLimitViolation,
            ThreatIndicatorType::SuspiciousActivity,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let decoded: ThreatIndicatorType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, decoded);
        }
    }

    #[test]
    fn test_threat_severity_level_variants() {
        let levels = [
            ThreatSeverityLevel::Low,
            ThreatSeverityLevel::Medium,
            ThreatSeverityLevel::High,
            ThreatSeverityLevel::Critical,
        ];
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let decoded: ThreatSeverityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, decoded);
        }
    }

    #[test]
    fn test_threat_indicator_data_serde() {
        let data = ThreatIndicatorData {
            threat_type: ThreatIndicatorType::IpBlock,
            indicator_value: "192.168.1.1".to_string(),
            severity: ThreatSeverityLevel::High,
            reason: "brute force".to_string(),
            ttl_seconds: 3600,
            source_node_id: "node1".to_string(),
            timestamp: 1000,
            site_scope: "global".to_string(),
            rate_limit_requests: Some(100),
            rate_limit_window_secs: Some(60),
            suspicious_pattern: Some("rapid_login".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        let decoded: ThreatIndicatorData = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.threat_type, ThreatIndicatorType::IpBlock);
        assert_eq!(decoded.indicator_value, "192.168.1.1");
        assert_eq!(decoded.severity, ThreatSeverityLevel::High);
    }

    #[test]
    fn test_threat_summary_serde() {
        let summary = ThreatSummary {
            critical_ips: 10,
            elevated_ips: 20,
            total_blocked_ips: 100,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let decoded: ThreatSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.critical_ips, 10);
        assert_eq!(decoded.total_blocked_ips, 100);
    }

    #[test]
    fn test_status_stats_serde() {
        let stats = StatusStats {
            total_requests: 1000,
            blocked_last_hour: 50,
            challenged_last_hour: 10,
            proxied_last_hour: 500,
            active_blocks: 25,
            active_violations: 5,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let decoded: StatusStats = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total_requests, 1000);
    }

    #[test]
    fn test_worker_status_info_serde() {
        let info = WorkerStatusInfo {
            id: 1,
            pid: 1234,
            port: 8080,
            status: "running".to_string(),
            requests: 100,
            blocked: 5,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: WorkerStatusInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, 1);
        assert_eq!(decoded.pid, 1234);
    }

    #[test]
    fn test_command_method_variants() {
        let methods = [
            CommandMethod::UnixSocket,
            CommandMethod::NamedPipe,
            CommandMethod::Signal,
        ];
        for method in methods {
            let json = serde_json::to_string(&method).unwrap();
            let decoded: CommandMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, decoded);
        }
    }

    #[test]
    fn test_current_timestamp() {
        let ts = crate::utils::current_timestamp();
        assert!(ts > 0);
    }

    #[test]
    fn test_master_command_serde() {
        let cmds = [
            SupervisorCommand::Stop { graceful: true },
            SupervisorCommand::Stop { graceful: false },
            SupervisorCommand::ReloadConfig,
            SupervisorCommand::Status,
            SupervisorCommand::HealthCheck,
        ];
        for cmd in cmds {
            let json = serde_json::to_string(&cmd).unwrap();
            let decoded: SupervisorCommand = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", cmd), format!("{:?}", decoded));
        }
    }

    #[test]
    fn test_message_serde() {
        let msg = Message::HealthCheckAck { timestamp: 12345 };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::HealthCheckAck { timestamp: 12345 }
        ));
    }

    #[test]
    fn test_message_worker_heartbeat_serde() {
        let metrics = WorkerMetricsPayload {
            total_requests: 100,
            blocked: 10,
            challenged: 5,
            proxied: 80,
            errors: 2,
            current_concurrent: 20,
            peak_concurrent: 50,
            avg_latency_ms: 25.0,
            p50_latency_ms: 20.0,
            p95_latency_ms: 50.0,
            p99_latency_ms: 100.0,
            uptime_secs: 3600,
            memory_bytes: 100_000_000,
            cpu_percent: 0.5,
            event_loop_lag_ms: 0,
            request_queue_time_ms: Default::default(),
            inline_cpu_phase_times_ms: HashMap::new(),
            body_buffering_bytes_total: 0,
            offload_submissions_total: 0,
            offload_timeouts_total: 0,
            offload_rejections_total: 0,
            offload_fallbacks_total: 0,
            blocked_by_type: std::collections::HashMap::new(),
            per_site: std::collections::HashMap::new(),
            static_cache_hits: 500,
            static_cache_misses: 50,
            bandwidth: crate::metrics::bandwidth::BandwidthPayload::default(),
            serverless_metrics: Vec::new(),
            health_score: 100.0,
            last_request_at: None,
            active_connections: 10,
            restart_count: 0,
        };
        let msg = Message::WorkerHeartbeat {
            id: WorkerId(1),
            timestamp: 1000,
            metrics,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(decoded, Message::WorkerHeartbeat { id, timestamp: 1000, .. } if id.0 == 1)
        );
    }

    #[test]
    fn test_cpu_task_request_validate_rejects_path_traversal_file_payload() {
        let msg = Message::CpuTaskRequest {
            request_id: 1,
            task_kind: CpuTaskKind::PoisonImage,
            priority: CpuTaskPriority::High,
            policy: CpuTaskPolicy::FailClosed,
            deadline_unix_ms: 0,
            payload_size_limit: 1024,
            output_size_limit: 2048,
            file_payload_path: Some("../escape.bin".to_string()),
            payload: CpuTaskPayload::PoisonImage {
                site_id: "site-a".to_string(),
                body: Vec::new(),
                last_modified: None,
                level: None,
                intensity: None,
                seed: None,
                max_dimension: None,
                jpeg_quality: None,
            },
        };

        let err = msg
            .validate()
            .expect_err("path traversal should be rejected");
        assert_eq!(err.field, "CpuTaskRequest.file_payload_path");
        assert!(err.message.contains("path traversal"));
    }

    #[test]
    fn test_cpu_task_request_validate_rejects_oversized_file_payload_path() {
        let msg = Message::CpuTaskRequest {
            request_id: 2,
            task_kind: CpuTaskKind::PoisonImage,
            priority: CpuTaskPriority::Normal,
            policy: CpuTaskPolicy::SkipTransform,
            deadline_unix_ms: 0,
            payload_size_limit: 1024,
            output_size_limit: 2048,
            file_payload_path: Some("a".repeat(MAX_PATH_LENGTH + 1)),
            payload: CpuTaskPayload::PoisonImage {
                site_id: "site-a".to_string(),
                body: Vec::new(),
                last_modified: None,
                level: None,
                intensity: None,
                seed: None,
                max_dimension: None,
                jpeg_quality: None,
            },
        };

        let err = msg
            .validate()
            .expect_err("oversized file path should be rejected");
        assert_eq!(err.field, "CpuTaskRequest.file_payload_path");
    }

    #[test]
    fn test_cpu_task_request_validate_rejects_task_kind_payload_mismatch() {
        let msg = Message::CpuTaskRequest {
            request_id: 3,
            task_kind: CpuTaskKind::Minify,
            priority: CpuTaskPriority::Normal,
            policy: CpuTaskPolicy::SkipTransform,
            deadline_unix_ms: 0,
            payload_size_limit: 1024,
            output_size_limit: 2048,
            file_payload_path: None,
            payload: CpuTaskPayload::GetCompressed {
                site_id: "site-a".to_string(),
                path: "/asset.js".to_string(),
                encoding: "gzip".to_string(),
            },
        };

        let err = msg
            .validate()
            .expect_err("task kind mismatch should be rejected");
        assert_eq!(err.field, "CpuTaskRequest.task_kind");
        assert!(err.message.contains("does not match payload"));
    }

    #[test]
    fn test_cpu_task_response_validate_rejects_task_kind_result_mismatch() {
        let msg = Message::CpuTaskResponse {
            request_id: 4,
            task_kind: CpuTaskKind::PoisonImage,
            result: CpuTaskResult::GetCompressed {
                content: vec![1, 2, 3],
            },
        };

        let err = msg
            .validate()
            .expect_err("task kind mismatch should be rejected");
        assert_eq!(err.field, "CpuTaskResponse.task_kind");
        assert!(err.message.contains("does not match result"));
    }

    #[test]
    fn test_cpu_task_request_validate_accepts_yara_scan_payload() {
        let msg = Message::CpuTaskRequest {
            request_id: 5,
            task_kind: CpuTaskKind::YaraScan,
            priority: CpuTaskPriority::High,
            policy: CpuTaskPolicy::FailClosed,
            deadline_unix_ms: 0,
            payload_size_limit: 1024 * 1024,
            output_size_limit: 1024 * 1024,
            file_payload_path: None,
            payload: CpuTaskPayload::YaraScan {
                site_id: "site-a".to_string(),
                body: vec![1, 2, 3],
                excluded_categories: vec!["archive".to_string()],
            },
        };

        msg.validate()
            .expect("YaraScan request envelope should validate");
    }

    #[test]
    fn test_cpu_task_response_validate_accepts_yara_scan_result() {
        let msg = Message::CpuTaskResponse {
            request_id: 6,
            task_kind: CpuTaskKind::YaraScan,
            result: CpuTaskResult::YaraScan {
                matches: vec!["test-rule".to_string()],
            },
        };

        msg.validate()
            .expect("YaraScan response envelope should validate");
    }

    #[test]
    fn test_cpu_task_cancel_validates() {
        let msg = Message::CpuTaskCancel {
            request_id: 7,
            task_kind: CpuTaskKind::PoisonImage,
        };
        msg.validate().expect("CpuTaskCancel should validate");
    }

    #[test]
    fn test_cpu_task_cancel_category_is_cpu_worker() {
        let msg = Message::CpuTaskCancel {
            request_id: 8,
            task_kind: CpuTaskKind::YaraScan,
        };
        assert_eq!(msg.category(), MessageCategory::CpuWorker);
    }
}
