use std::io;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::ipc_framing::{read_message_sync, write_message_sync, DEFAULT_BUFFER_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandMethod {
    UnixSocket,
    NamedPipe,
    Signal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasterCommand {
    Stop { graceful: bool },
    ReloadConfig,
    Status,
    HealthCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterStatus {
    pub master_pid: u32,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusStats {
    pub total_requests: u64,
    pub blocked_last_hour: u64,
    pub challenged_last_hour: u64,
    pub proxied_last_hour: u64,
    pub active_blocks: usize,
    pub active_violations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Unique identifier for a worker process within the master's pool.
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

/// IPC messages exchanged between overseer, master, and worker processes.
///
/// Messages are serialized as JSON over Unix domain sockets. Each variant
/// IPC Message variants grouped by concern (documentation-level grouping).
///
/// The flat variant structure is maintained for postcard wire-format stability.
/// Use these group names when adding new variants:
///
/// - **Worker Lifecycle**: WorkerStarted, WorkerReady, WorkerHeartbeat,
///   WorkerRequestLog, WorkerShutdownComplete, WorkerError
/// - **Master Commands**: MasterShutdown, MasterConfigReload,
///   MasterProcessConfigReload, MasterSupervisorConfigReload, MasterHealthCheck,
///   MasterResizeThreadpool, HealthCheckAck, WorkerResizeAck
/// - **Static Worker**: StaticWorkerStarted, StaticWorkerReady,
///   StaticWorkerHeartbeat, StaticWorkerRequestLog, StaticWorkerShutdownComplete,
///   StaticWorkerBackgroundTasksDone, StaticWorkerResizeAck, StaticWorkerScan,
///   StaticWorkerCacheUpdate, StaticWorkerDrain, StaticWorkerDrained,
///   StaticWorkerDrainStatus
/// - **Threat Intel**: ThreatIndicatorAnnounce, ThreatIndicatorFromMesh,
///   ThreatSyncRequest, ThreatSyncResponse, BlocklistRequest, BlocklistResponse
/// - **Blocklist & Rules**: BlocklistUpdate, RulePatternsUpdate,
///   BlocklistWriteComplete
/// - **Static Content**: MinifyRequest, MinifyResponse, MinifyError,
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
/// - **Upgrade**: UpgradeReady, UpgradeFailed, OverseerUpgradePrepare,
///   OverseerUpgradePrepareAck, OverseerUpgradeCommit,
///   OverseerUpgradeCommitAck, OverseerUpgradeRollback,
///   OverseerUpgradeRollbackAck, OverseerCommitUpgrade,
///   OverseerCommitUpgradeAck
/// - **Overseer**: OverseerDrainWorkers, OverseerDrainWorkersAck,
///   OverseerGetStatus, OverseerStatusResponse, OverseerDualMasterPrepare,
///   OverseerDualMasterPrepareAck
/// - **Master Drain**: MasterDrainMode, MasterDrainModeAck,
///   MasterReportConnections, MasterConnectionsReport, MasterStopAccepting,
///   MasterStopAcceptingAck, MasterDrainStatus
/// - **Drain Protocol**: DrainRequest, DrainStatusRequest, DrainStatusResponse,
///   DrainComplete, StopAccepting, StopAcceptingAck, RestoreFromDrain,
///   RestoreFromDrainAck
/// - **Socket Handoff**: SocketHandoffRequest, SocketHandoffReady,
///   SocketHandoffComplete, SocketHandoffFailed, WindowsSocketInfo
/// - **Worker Restart**: RestartWorkerRequest, RestartWorkerResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    HealthCheckAck {
        timestamp: u64,
    },
    WorkerResizeAck {
        id: WorkerId,
        worker_threads: u32,
    },
    StaticWorkerStarted {
        worker_id: usize,
        pid: u32,
    },
    StaticWorkerReady {
        worker_id: usize,
    },
    StaticWorkerHeartbeat {
        worker_id: usize,
        timestamp: u64,
        static_cache_hits: u64,
        static_cache_misses: u64,
    },
    StaticWorkerRequestLog {
        worker_id: usize,
        log: RequestLogPayload,
    },
    StaticWorkerShutdownComplete {
        worker_id: usize,
    },
    StaticWorkerBackgroundTasksDone {
        worker_id: usize,
    },
    StaticWorkerResizeAck {
        worker_id: usize,
        worker_threads: u32,
    },
    StaticWorkerScan {
        site_id: String,
    },
    StaticWorkerCacheUpdate {
        site_id: String,
        path: String,
        minified_path: String,
    },
    StaticWorkerDrain {
        timeout_secs: u64,
        drain_id: u64,
    },
    StaticWorkerDrained {
        worker_id: usize,
        remaining_tasks: u64,
        drain_id: u64,
    },
    StaticWorkerDrainStatus {
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
    OverseerUpgradePrepare {
        binary_path: String,
        config_path: Option<String>,
        version: String,
    },
    OverseerUpgradePrepareAck {
        ready: bool,
        error: Option<String>,
    },
    OverseerUpgradeCommit {
        timeout_secs: u64,
    },
    OverseerUpgradeCommitAck {
        success: bool,
        error: Option<String>,
    },
    OverseerUpgradeRollback {
        reason: String,
    },
    OverseerUpgradeRollbackAck {
        success: bool,
        error: Option<String>,
    },
    OverseerDrainWorkers {
        timeout_secs: u64,
    },
    OverseerDrainWorkersAck {
        drained_count: usize,
        remaining_connections: u64,
    },
    OverseerGetStatus,
    OverseerStatusResponse {
        master_pid: u32,
        workers: Vec<WorkerStatusInfo>,
        uptime_secs: u64,
        version: String,
    },
    OverseerDualMasterPrepare {
        binary_path: String,
        config_path: Option<String>,
        version: String,
    },
    OverseerDualMasterPrepareAck {
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
    OverseerCommitUpgrade {
        old_master_timeout_secs: u64,
    },
    OverseerCommitUpgradeAck {
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
            | Message::HealthCheckAck { .. }
            | Message::WorkerResizeAck { .. }
            | Message::StaticWorkerStarted { .. }
            | Message::StaticWorkerReady { .. }
            | Message::StaticWorkerHeartbeat { .. }
            | Message::StaticWorkerShutdownComplete { .. }
            | Message::StaticWorkerBackgroundTasksDone { .. }
            | Message::StaticWorkerResizeAck { .. }
            | Message::StaticWorkerDrain { .. }
            | Message::StaticWorkerDrained { .. }
            | Message::StaticWorkerDrainStatus { .. }
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
            | Message::OverseerUpgradeCommit { .. }
            | Message::OverseerDrainWorkers { .. }
            | Message::OverseerDrainWorkersAck { .. }
            | Message::OverseerGetStatus
            | Message::MasterDrainMode { .. }
            | Message::MasterDrainModeAck { .. }
            | Message::MasterReportConnections { .. }
            | Message::MasterConnectionsReport { .. }
            | Message::MasterStopAccepting { .. }
            | Message::MasterStopAcceptingAck { .. }
            | Message::WorkerConnectionCount { .. }
            | Message::WorkerDrainComplete { .. }
            | Message::OverseerCommitUpgrade { .. }
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
            | Message::RestartWorkerResponse { .. } => Ok(()),

            // Variants with string fields that need validation
            Message::WorkerError { error, .. } => {
                check_str("WorkerError.error", error, MAX_STRING_LENGTH)
            }
            Message::MasterConfigReload { config_path } => check_str(
                "MasterConfigReload.config_path",
                config_path,
                MAX_PATH_LENGTH,
            ),
            Message::StaticWorkerScan { site_id } => {
                check_str("StaticWorkerScan.site_id", site_id, MAX_STRING_LENGTH)
            }
            Message::StaticWorkerCacheUpdate {
                site_id,
                path,
                minified_path,
            } => {
                check_str(
                    "StaticWorkerCacheUpdate.site_id",
                    site_id,
                    MAX_STRING_LENGTH,
                )?;
                check_str("StaticWorkerCacheUpdate.path", path, MAX_PATH_LENGTH)?;
                check_str(
                    "StaticWorkerCacheUpdate.minified_path",
                    minified_path,
                    MAX_PATH_LENGTH,
                )
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
            Message::AppServerStarted {
                site_id,
                socket_path,
                ..
            } => {
                check_str("AppServerStarted.site_id", site_id, MAX_STRING_LENGTH)?;
                check_opt_str("AppServerStarted.socket_path", socket_path, MAX_PATH_LENGTH)
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
            Message::WorkerRequestLog { log, .. } | Message::StaticWorkerRequestLog { log, .. } => {
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
            Message::OverseerUpgradePrepare {
                binary_path,
                config_path,
                version,
            } => {
                check_str("binary_path", binary_path, MAX_PATH_LENGTH)?;
                check_opt_str("config_path", config_path, MAX_PATH_LENGTH)?;
                check_str("version", version, MAX_STRING_LENGTH)
            }
            Message::OverseerUpgradePrepareAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::OverseerUpgradeCommitAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::OverseerUpgradeRollback { reason } => {
                check_str("reason", reason, MAX_STRING_LENGTH)
            }
            Message::OverseerUpgradeRollbackAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::OverseerStatusResponse { version, .. } => {
                check_str("version", version, MAX_STRING_LENGTH)
            }
            Message::OverseerDualMasterPrepare {
                binary_path,
                config_path,
                version,
            } => {
                check_str("binary_path", binary_path, MAX_PATH_LENGTH)?;
                check_opt_str("config_path", config_path, MAX_PATH_LENGTH)?;
                check_str("version", version, MAX_STRING_LENGTH)
            }
            Message::OverseerDualMasterPrepareAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::OverseerCommitUpgradeAck { error, .. } => {
                check_opt_str("error", error, MAX_STRING_LENGTH)
            }
            Message::SocketHandoffRequest { socket_path } => {
                check_str("socket_path", socket_path, MAX_PATH_LENGTH)
            }
            Message::SocketHandoffFailed { error } => check_str("error", error, MAX_STRING_LENGTH),
            // NOTE: Do NOT add a catch-all here. All variants must be explicitly handled
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
            | Message::WorkerError { .. } => MessageCategory::WorkerLifecycle,

            Message::MasterShutdown { .. }
            | Message::MasterConfigReload { .. }
            | Message::MasterProcessConfigReload { .. }
            | Message::MasterSupervisorConfigReload { .. }
            | Message::MasterHealthCheck { .. }
            | Message::MasterResizeThreadpool { .. }
            | Message::HealthCheckAck { .. }
            | Message::WorkerResizeAck { .. } => MessageCategory::MasterCommand,

            Message::StaticWorkerStarted { .. }
            | Message::StaticWorkerReady { .. }
            | Message::StaticWorkerHeartbeat { .. }
            | Message::StaticWorkerRequestLog { .. }
            | Message::StaticWorkerShutdownComplete { .. }
            | Message::StaticWorkerBackgroundTasksDone { .. }
            | Message::StaticWorkerResizeAck { .. }
            | Message::StaticWorkerScan { .. }
            | Message::StaticWorkerCacheUpdate { .. }
            | Message::StaticWorkerDrain { .. }
            | Message::StaticWorkerDrained { .. }
            | Message::StaticWorkerDrainStatus { .. } => MessageCategory::StaticWorker,

            Message::ThreatIndicatorAnnounce { .. }
            | Message::ThreatIndicatorFromMesh { .. }
            | Message::ThreatSyncRequest { .. }
            | Message::ThreatSyncResponse { .. }
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
            | Message::GetCompressedResponse { .. } => MessageCategory::StaticContent,

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
            | Message::OverseerUpgradePrepare { .. }
            | Message::OverseerUpgradePrepareAck { .. }
            | Message::OverseerUpgradeCommit { .. }
            | Message::OverseerUpgradeCommitAck { .. }
            | Message::OverseerUpgradeRollback { .. }
            | Message::OverseerUpgradeRollbackAck { .. }
            | Message::OverseerCommitUpgrade { .. }
            | Message::OverseerCommitUpgradeAck { .. } => MessageCategory::Upgrade,

            Message::OverseerDrainWorkers { .. }
            | Message::OverseerDrainWorkersAck { .. }
            | Message::OverseerGetStatus
            | Message::OverseerStatusResponse { .. }
            | Message::OverseerDualMasterPrepare { .. }
            | Message::OverseerDualMasterPrepareAck { .. } => MessageCategory::Overseer,

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
            | Message::WindowsSocketInfo { .. } => MessageCategory::SocketHandoff,

            Message::RestartWorkerRequest { .. } | Message::RestartWorkerResponse { .. } => {
                MessageCategory::WorkerRestart
            }
        }
    }

    /// Returns true if this message is a lifecycle message (started, ready, heartbeat, shutdown).
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self.category(),
            MessageCategory::WorkerLifecycle
                | MessageCategory::StaticWorker
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
}

/// IPC Message concern groups for logical organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCategory {
    WorkerLifecycle,
    MasterCommand,
    StaticWorker,
    ThreatIntel,
    BlocklistRules,
    StaticContent,
    AppServer,
    UnifiedServer,
    WorkerDrain,
    Upgrade,
    Overseer,
    MasterDrain,
    DrainProtocol,
    SocketHandoff,
    WorkerRestart,
}

impl std::fmt::Display for MessageCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageCategory::WorkerLifecycle => write!(f, "WorkerLifecycle"),
            MessageCategory::MasterCommand => write!(f, "MasterCommand"),
            MessageCategory::StaticWorker => write!(f, "StaticWorker"),
            MessageCategory::ThreatIntel => write!(f, "ThreatIntel"),
            MessageCategory::BlocklistRules => write!(f, "BlocklistRules"),
            MessageCategory::StaticContent => write!(f, "StaticContent"),
            MessageCategory::AppServer => write!(f, "AppServer"),
            MessageCategory::UnifiedServer => write!(f, "UnifiedServer"),
            MessageCategory::WorkerDrain => write!(f, "WorkerDrain"),
            MessageCategory::Upgrade => write!(f, "Upgrade"),
            MessageCategory::Overseer => write!(f, "Overseer"),
            MessageCategory::MasterDrain => write!(f, "MasterDrain"),
            MessageCategory::DrainProtocol => write!(f, "DrainProtocol"),
            MessageCategory::SocketHandoff => write!(f, "SocketHandoff"),
            MessageCategory::WorkerRestart => write!(f, "WorkerRestart"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeModePayload {
    ReusePort,
    PortSwap { temp_port_offset: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMetricsPayload {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub blocked_by_type: std::collections::HashMap<String, u64>,
    pub upstream_healthy: bool,
    pub proxy_cache_hits: u64,
    pub proxy_cache_misses: u64,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogPayload {
    pub timestamp: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_time_ms: u32,
    pub site_id: String,
    pub user_agent: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerMetricsPayload {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub uptime_secs: u64,
    pub memory_bytes: u64,
    pub cpu_percent: f64,
    pub blocked_by_type: std::collections::HashMap<String, u64>,
    pub per_site: std::collections::HashMap<String, SiteMetricsPayload>,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
    pub bandwidth: crate::metrics::bandwidth::BandwidthPayload,
}

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
/// This is a blocking wrapper around `UnixStream` (Unix) or `std::fs::File`
/// (Windows named pipe) that provides length-prefixed JSON framing via
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
/// | Message signing | Not supported | Supported via `IpcSigner` |
/// | Recv with timeout | Polling via `recv()` | Native `recv_with_timeout()` |
/// | AsyncRead/Write | No | Yes |
/// | Use case | Static worker threads, command handling | Master↔Worker IPC, mesh transport |
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
            .unwrap_or("maluwaf-master");
        format!("\\\\.\\pipe\\{}", pipe_name)
    }
}

pub fn get_platform_info() -> crate::platform::Platform {
    crate::platform::platform()
}

pub fn connect_to_master(path: &std::path::Path) -> io::Result<IpcStream> {
    #[cfg(unix)]
    {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true).ok();
        Ok(IpcStream {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        })
    }

    #[cfg(windows)]
    {
        let pipe_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("maluwaf-master");
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
    #[cfg(unix)]
    pub fn new(stream: UnixStream) -> Self {
        stream.set_nonblocking(true).ok();
        Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        }
    }

    #[cfg(windows)]
    pub fn new(stream: std::fs::File) -> Self {
        Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        }
    }

    #[cfg(unix)]
    pub fn connect_unix(path: &std::path::Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true).ok();
        Ok(Self {
            stream,
            read_buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        })
    }

    #[cfg(windows)]
    pub fn connect_unix(path: &std::path::Path) -> io::Result<Self> {
        connect_to_master(path)
    }

    pub fn send(&mut self, msg: &Message) -> io::Result<()> {
        write_message_sync(&mut self.stream, msg)
    }

    pub fn try_recv(&mut self) -> io::Result<Option<Message>> {
        read_message_sync(&mut self.stream, &mut self.read_buffer)
    }

    pub fn recv(&mut self, timeout_ms: u64) -> io::Result<Option<Message>> {
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        let mut sleep_duration = 1u64;
        let max_sleep = 50u64;

        loop {
            match self.try_recv() {
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
            MasterCommand::Stop { graceful: true },
            MasterCommand::Stop { graceful: false },
            MasterCommand::ReloadConfig,
            MasterCommand::Status,
            MasterCommand::HealthCheck,
        ];
        for cmd in cmds {
            let json = serde_json::to_string(&cmd).unwrap();
            let decoded: MasterCommand = serde_json::from_str(&json).unwrap();
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
            blocked_by_type: std::collections::HashMap::new(),
            per_site: std::collections::HashMap::new(),
            static_cache_hits: 500,
            static_cache_misses: 50,
            bandwidth: crate::metrics::bandwidth::BandwidthPayload::default(),
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
}
