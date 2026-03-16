pub mod command;
pub mod ipc;
pub mod ipc_framing;
pub mod ipc_signed;
pub mod ipc_transport;
pub mod ipc_rate_limit;
pub mod ipc_pool;
pub mod manager;
pub mod pidfile;
pub mod socket_fd;
pub mod socket_path;

pub use ipc_rate_limit::{IpcRateLimiter, RateLimitExceeded};
pub use ipc_rate_limit::config::IpcRateLimitConfig;
pub use ipc_pool::{IpcConnectionPool, PoolError, ConnectionPoolStats};
pub use ipc_pool::config::IpcConnectionPoolConfig;

pub use ipc_signed::{IpcSigner, SignedIpcMessage, generate_session_key};

#[cfg(windows)]
pub mod ipc_windows;

pub use command::{CommandClient, CommandError, CommandResponse};
pub use ipc::{
    current_timestamp, connect_to_master, get_ipc_path, CommandMethod, ErrorSeverity, ErrorCode,
    MasterCommand, MasterStatus, Message, StatusStats, ThreatSummary, WorkerId, WorkerMetricsPayload,
    WorkerStatus, WorkerStatusInfo, IpcStream,
    ThreatIndicatorType, ThreatSeverityLevel, ThreatIndicatorData,
    BoxResult, BoxError, SiteMetricsPayload, RequestLogPayload,
};
pub use ipc_framing::{
    read_exact_message_sync, read_message_sync, write_message_sync, MAX_MESSAGE_SIZE,
};
pub use ipc_transport::{
    connect_to_endpoint, connect_to_endpoint_signed,
    connect_to_master_async, connect_to_master_signed,
    connect_to_static_worker_async, connect_to_static_worker_signed,
    connect_to_commands_async, connect_to_commands_signed,
    IpcEndpoint, IpcListener, IpcStream as AsyncIpcStream,
};
#[cfg(windows)]
pub use ipc::WindowsIpcListener;
pub use manager::{ProcessEvent, ProcessManager, ProcessManagerConfig, WorkerConfig, start_health_monitor, check_port_available, check_ports_available};
pub use pidfile::{OverseerLockFile, OverseerLockError, PidFileManager};
pub use socket_fd::{
    close_fd, create_listening_socket, create_listening_socket_v6, raw_fd_to_tcp_listener,
    raw_fd_to_tcp_stream, is_reuse_port_supported, SocketFDError, SocketFDPassing, SocketHolder,
    SocketInfo, SocketType,
};
pub use socket_path::{
    get_secure_socket_path, set_socket_permissions, get_master_socket_path,
    get_versioned_master_socket_path, get_current_master_generation, set_master_generation,
    next_master_generation, resolve_master_socket_for_upgrade, find_active_master_socket,
    cleanup_old_master_sockets,
};

pub use crate::platform::{Platform, platform, is_socket_fd_passing_supported};
