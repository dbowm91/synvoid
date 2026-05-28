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
pub mod manager;
pub mod pidfile;
pub mod socket_fd;
pub mod socket_path;
pub mod worker;

pub use ipc_pool::config::IpcConnectionPoolConfig;
pub use ipc_pool::{ConnectionPoolStats, IpcConnectionPool, PoolError};
pub use ipc_rate_limit::config::IpcRateLimitConfig;
pub use ipc_rate_limit::{IpcRateLimiter, RateLimitExceeded};

pub use ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

#[cfg(windows)]
pub mod ipc_windows;

use std::sync::atomic::{AtomicUsize, Ordering};
pub static CURRENT_WORKER_ID: AtomicUsize = AtomicUsize::new(0);

pub fn set_current_worker_id(id: usize) {
    CURRENT_WORKER_ID.store(id, Ordering::SeqCst);
}

pub fn get_current_worker_id() -> usize {
    CURRENT_WORKER_ID.load(Ordering::SeqCst)
}

pub use crate::utils::current_timestamp;
pub use command::{CommandClient, CommandError, CommandResponse};
#[cfg(windows)]
pub use ipc::WindowsIpcListener;
pub use ipc::{
    connect_to_supervisor, get_ipc_path, CommandMethod, ErrorCode, ErrorSeverity, IpcStream,
    IpcValidationError, SupervisorCommand, SupervisorStatus, Message, RequestLogPayload,
    SiteMetricsPayload, StatusStats, ThreatIndicatorData, ThreatIndicatorType, ThreatSeverityLevel,
    ThreatSummary, WorkerId, WorkerMetricsPayload, WorkerStatus, WorkerStatusInfo,
};
pub use ipc_framing::{
    read_exact_message_sync, read_message_sync, write_message_sync, MAX_MESSAGE_SIZE,
};
pub use ipc_transport::{
    connect_to_commands_async, connect_to_commands_signed, connect_to_endpoint,
    connect_to_endpoint_signed, connect_to_supervisor_async, connect_to_supervisor_signed,
    connect_to_static_worker_async, connect_to_static_worker_signed, IpcEndpoint, IpcListener,
    IpcStream as AsyncIpcStream,
};
pub use manager::{
    check_port_available, check_ports_available, start_health_monitor, ProcessEvent,
    ProcessManager, ProcessManagerConfig, WorkerConfig,
};
pub use pidfile::{SupervisorLockError, SupervisorLockFile, PidFileManager};
pub use socket_fd::{
    close_fd, create_listening_socket, create_listening_socket_v6, is_reuse_port_supported,
    raw_fd_to_tcp_listener, raw_fd_to_tcp_stream, SocketFDError, SocketFDPassing, SocketHolder,
    SocketInfo, SocketType,
};
pub use socket_path::{
    cleanup_old_supervisor_sockets, find_active_supervisor_socket, get_current_supervisor_generation,
    get_supervisor_socket_path, get_secure_socket_path, get_static_worker_socket_path,
    get_versioned_supervisor_socket_path, next_supervisor_generation, resolve_supervisor_socket_for_upgrade,
    set_supervisor_generation, set_socket_permissions,
};
pub use worker::{
    BaseWorkerProcess, StaticWorkerProcess, UnifiedServerWorkerProcess, WorkerProcess,
    WorkerProcessBase,
};

pub use crate::platform::{is_socket_fd_passing_supported, platform, Platform};
