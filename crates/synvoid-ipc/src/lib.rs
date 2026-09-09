//! Inter-process communication and process management.
//!
//! Provides IPC transport over Unix domain sockets, message framing,
//! rate limiting for IPC connections, and connection pooling.

pub mod command;
pub mod ipc;
pub mod ipc_framing;
pub mod ipc_pool;
pub mod ipc_rate_limit;
pub mod ipc_signed;
pub mod ipc_transport;
pub mod jail_process;
pub mod jail_protocol;
pub mod manager;
pub mod pidfile;
pub mod socket_path;
pub mod worker;

pub use ipc_pool::config::IpcConnectionPoolConfig;
pub use ipc_pool::{ConnectionPoolStats, IpcConnectionPool, PoolError};
pub use ipc_rate_limit::config::IpcRateLimitConfig;
pub use ipc_rate_limit::{IpcRateLimiter, RateLimitExceeded};

pub use ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

pub use jail_process::{
    serve_jail_connection, JailHandle, JailHandleConfig, JailHandler, JailSpawnSpec,
    RestartTracker, ServeOutcome,
};
pub use jail_protocol::{
    decode_request, decode_response, encode_request, encode_response, jail_metrics_snapshot,
    read_frame, record_jail_exit, record_jail_failure, record_jail_invocation, record_jail_restart,
    record_jail_shutdown, record_jail_start, resolve_route, sha256_hex, verify_sha256_hex,
    write_frame, FrameRead, IsolationPolicy, JailError, JailErrorCode, JailErrorDto,
    JailHookCapabilities, JailKind, JailMetricsSnapshot, JailOperation, JailOutput, JailRequest,
    JailResponse, JailResult, JailRoute, YaraMatchDto, JAIL_DEFAULT_CALL_TIMEOUT_MS, JAIL_MAGIC,
    JAIL_MAX_ERROR_MESSAGE, JAIL_MAX_FRAME_BYTES, JAIL_MAX_HEADERS, JAIL_MAX_HEADER_NAME_LEN,
    JAIL_MAX_HEADER_VALUE_LEN, JAIL_MAX_ID_LEN, JAIL_MAX_INVOKE_INPUT_BYTES,
    JAIL_MAX_INVOKE_OUTPUT_BYTES, JAIL_MAX_MATCHES, JAIL_MAX_METHOD_LEN, JAIL_MAX_MODULES,
    JAIL_MAX_MODULE_BYTES, JAIL_MAX_RESTARTS, JAIL_MAX_RULESETS, JAIL_MAX_RULES_BYTES,
    JAIL_MAX_SCAN_INPUT_BYTES, JAIL_MAX_TEXT_FIELD, JAIL_MAX_TIMEOUT_MS, JAIL_MAX_URI_LEN,
    JAIL_MIN_TIMEOUT_MS, JAIL_PROTOCOL_VERSION, JAIL_RESTART_BASE_BACKOFF_MS,
    JAIL_RESTART_MAX_BACKOFF_MS, JAIL_SHUTDOWN_GRACE_MS,
};

#[cfg(windows)]
pub mod ipc_windows;

pub use synvoid_utils::{get_current_worker_id, set_current_worker_id, CURRENT_WORKER_ID};

pub use command::{CommandClient, CommandError, CommandResponse};
#[cfg(windows)]
pub use ipc::WindowsIpcListener;
pub use ipc::{
    connect_to_supervisor, get_ipc_path, CommandMethod, CpuOffloadStats, CpuTaskErrorCode,
    CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, CpuTaskPriority, CpuTaskResult, ErrorCode,
    ErrorSeverity, IpcStream, IpcValidationError, Message, RequestLogPayload, SiteMetricsPayload,
    StatusStats, SupervisorCommand, SupervisorStatus, ThreatIndicatorData, ThreatIndicatorType,
    ThreatSeverityLevel, ThreatSummary, WorkerId, WorkerMetricsPayload, WorkerStatus,
    WorkerStatusInfo,
};
pub use ipc_framing::{
    read_exact_message_sync, read_message_sync, write_message_sync, MAX_MESSAGE_SIZE,
};
pub use ipc_transport::{
    connect_to_commands_async, connect_to_commands_signed, connect_to_cpu_worker_async,
    connect_to_cpu_worker_signed, connect_to_endpoint, connect_to_endpoint_signed,
    connect_to_supervisor_async, connect_to_supervisor_signed, IpcEndpoint, IpcListener,
    IpcStream as AsyncIpcStream,
};
pub use manager::{
    check_port_available, check_ports_available, start_health_monitor, ProcessEvent,
    ProcessManager, ProcessManagerConfig, WorkerConfig,
};
pub use pidfile::{PidFileManager, SupervisorLockError, SupervisorLockFile};
pub use socket_path::{
    cleanup_old_supervisor_sockets, find_active_supervisor_socket, get_cpu_worker_socket_path,
    get_current_supervisor_generation, get_secure_socket_path, get_supervisor_socket_path,
    get_versioned_supervisor_socket_path, next_supervisor_generation,
    resolve_supervisor_socket_for_upgrade, set_socket_permissions, set_supervisor_generation,
};
pub use synvoid_utils::current_timestamp;
pub use worker::{
    BaseWorkerProcess, CpuWorkerProcess, UnifiedServerWorkerProcess, WorkerProcess,
    WorkerProcessBase,
};

pub use synvoid_platform::{is_socket_fd_passing_supported, platform, Platform};
