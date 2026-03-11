pub mod command;
pub mod ipc;
pub mod ipc_backend;
pub mod manager;
pub mod pidfile;

#[cfg(unix)]
pub mod ipc_unix;

#[cfg(windows)]
pub mod ipc_windows;

pub use command::{CommandClient, CommandError, CommandResponse};
pub use ipc::{IpcStream, Message, WorkerId, WorkerMetricsPayload, WorkerStatus, current_timestamp, MasterCommand, MasterStatus, WorkerStatusInfo, StatusStats, ThreatSummary, CommandMethod, connect_to_master, get_ipc_path};
#[cfg(windows)]
pub use ipc::WindowsIpcListener;
pub use ipc_backend::{IpcBackend, IpcConnection, WorkerStatusInfo as IpcWorkerStatusInfo};
pub use manager::{ProcessManager, ProcessManagerConfig, ProcessEvent, WorkerConfig, start_health_monitor};
pub use pidfile::PidFileManager;
