use std::io;
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::ipc_framing::{read_message_sync, write_message_sync, DEFAULT_BUFFER_SIZE};

pub type BoxResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

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

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
